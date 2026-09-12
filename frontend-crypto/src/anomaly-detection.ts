/**
 * vault-crypto/src/anomaly-detection.ts
 *
 * Lightweight, fully on-device anomaly signals for vault access events.
 *
 * HONEST SCOPE NOTE: this is NOT a trained machine-learning model — shipping
 * a real "anomaly detection AI" would require a labeled dataset, a training
 * pipeline, and ongoing retraining, none of which exist here. What this
 * module actually provides is a small set of well-understood, explainable
 * STATISTICAL heuristics (velocity/impossible-travel check, access-time
 * z-score, geographic jump distance) that run entirely client-side, so the
 * zero-knowledge server never needs to see access metadata to benefit from
 * them. This is deliberately conservative: false "AI" claims here would be
 * actively misleading for a security product.
 *
 * All checks operate on data the client already has locally (a rolling
 * history of past unlock events) and never require the server to log
 * anything beyond opaque encrypted blobs.
 */

export interface AccessEvent {
  timestampMs: number;
  latitude?: number;
  longitude?: number;
  deviceId: string;
}

export interface AnomalySignal {
  type: 'impossible-travel' | 'unusual-hour' | 'new-device' | 'burst-attempts';
  severity: 'low' | 'medium' | 'high';
  detail: string;
}

const EARTH_RADIUS_KM = 6371;

function haversineDistanceKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return EARTH_RADIUS_KM * c;
}

/**
 * Flags a physically implausible sequence of logins, e.g. Mumbai then
 * London 20 minutes later (~7,200 km, which would require ~21,700 km/h).
 * Commercial airliner cruise speed (~900 km/h) is used as the plausibility
 * ceiling, generously doubled to reduce false positives from GPS drift.
 */
export function checkImpossibleTravel(
  previous: AccessEvent,
  current: AccessEvent,
  maxPlausibleSpeedKmh = 1800,
): AnomalySignal | null {
  if (
    previous.latitude === undefined ||
    previous.longitude === undefined ||
    current.latitude === undefined ||
    current.longitude === undefined
  ) {
    return null; // insufficient data — do not guess
  }
  const distanceKm = haversineDistanceKm(
    previous.latitude,
    previous.longitude,
    current.latitude,
    current.longitude,
  );
  const hoursElapsed = (current.timestampMs - previous.timestampMs) / (1000 * 60 * 60);
  if (hoursElapsed <= 0) return null;
  const impliedSpeed = distanceKm / hoursElapsed;
  if (impliedSpeed > maxPlausibleSpeedKmh) {
    return {
      type: 'impossible-travel',
      severity: impliedSpeed > maxPlausibleSpeedKmh * 3 ? 'high' : 'medium',
      detail: `Implied travel speed ~${Math.round(impliedSpeed)} km/h between consecutive unlocks (${Math.round(distanceKm)} km in ${hoursElapsed.toFixed(2)}h).`,
    };
  }
  return null;
}

/**
 * Flags access at an hour that is statistically unusual for this specific
 * user, using a simple z-score against their own rolling history (never
 * compared against other users — that would require server-visible data).
 */
export function checkUnusualHour(history: AccessEvent[], current: AccessEvent, zThreshold = 2.5): AnomalySignal | null {
  if (history.length < 10) return null; // not enough history to judge "usual"
  const hours = history.map((e) => new Date(e.timestampMs).getHours());
  const mean = hours.reduce((a, b) => a + b, 0) / hours.length;
  const variance = hours.reduce((sum, h) => sum + (h - mean) ** 2, 0) / hours.length;
  const stddev = Math.sqrt(variance) || 1; // avoid divide-by-zero for perfectly regular history
  const currentHour = new Date(current.timestampMs).getHours();
  const z = Math.abs(currentHour - mean) / stddev;
  if (z > zThreshold) {
    return {
      type: 'unusual-hour',
      severity: z > zThreshold * 1.5 ? 'medium' : 'low',
      detail: `Access at hour ${currentHour}, which is ${z.toFixed(1)} standard deviations from this user's typical access hour (${mean.toFixed(1)}).`,
    };
  }
  return null;
}

export function checkNewDevice(history: AccessEvent[], current: AccessEvent): AnomalySignal | null {
  const knownDevices = new Set(history.map((e) => e.deviceId));
  if (history.length >= 3 && !knownDevices.has(current.deviceId)) {
    return {
      type: 'new-device',
      severity: 'medium',
      detail: `Device ID "${current.deviceId}" has not been seen in this vault's access history.`,
    };
  }
  return null;
}

export function checkBurstAttempts(recentAttempts: AccessEvent[], windowMs = 60000, maxInWindow = 5): AnomalySignal | null {
  const now = Date.now();
  const inWindow = recentAttempts.filter((e) => now - e.timestampMs <= windowMs);
  if (inWindow.length > maxInWindow) {
    return {
      type: 'burst-attempts',
      severity: 'high',
      detail: `${inWindow.length} access attempts within the last ${windowMs / 1000}s (threshold: ${maxInWindow}).`,
    };
  }
  return null;
}

/**
 * Runs all checks and returns every signal fired. Callers should decide
 * their own policy (e.g. require step-up WebAuthn re-auth on 'medium'+,
 * or trigger the VDF lockout delay from vdf.ts on 'high').
 */
export function evaluateAccessEvent(
  history: AccessEvent[],
  recentAttempts: AccessEvent[],
  current: AccessEvent,
): AnomalySignal[] {
  const signals: AnomalySignal[] = [];
  const previous = history[history.length - 1];
  if (previous) {
    const travel = checkImpossibleTravel(previous, current);
    if (travel) signals.push(travel);
  }
  const hourSignal = checkUnusualHour(history, current);
  if (hourSignal) signals.push(hourSignal);
  const deviceSignal = checkNewDevice(history, current);
  if (deviceSignal) signals.push(deviceSignal);
  const burstSignal = checkBurstAttempts(recentAttempts);
  if (burstSignal) signals.push(burstSignal);
  return signals;
}
