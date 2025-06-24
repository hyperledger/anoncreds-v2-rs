import { ResponseError } from "VCP";

export type IndexSignature3Level<T> = {
  [outerKey: string]: {
    [middleKey: string]: {
      [innerKey: string]: T
    }
  }
};

export type Map3Level<T> = Map<string, Map<string, Map<string, T>>>;

/**
 * Converts a 3-level Map structure back to a nested object
 *
 * @param map The 3-level Map structure to convert
 * @returns A nested object
 */
export function mapToObject<T>(
  m: Map3Level<T>
) : IndexSignature3Level<T> {
  const result: IndexSignature3Level<T> = {};
  m.forEach((middleMap, outerKey) => {
    result[outerKey] = {};
    middleMap.forEach((innerMap, middleKey) => {
      result[outerKey][middleKey] = {};
      innerMap.forEach((value, innerKey) => {
        result[outerKey][middleKey][innerKey] = value;
      });
    });
  });
  return result;
}

export function isErrorA<T extends { name?: string }>(
  name: string,
  err: unknown
): err is T {
  return (
    typeof err === 'object' &&
    err !== null &&
    'name' in err &&
    (err as { name?: string }).name === name
  );
}

export function describeValue(x: unknown): string {
  const lines: string[] = [];

  const describeValue = (value: unknown): string => {
    if (value === undefined) return "undefined";
    if (value === null) return "null";
    if (typeof value === "function") return `[Function: ${value.name || "anonymous"}]`;
    if (typeof value === "object") {
      try {
        return JSON.stringify(value, null, 2);
      } catch {
        return value?.toString?.() ?? "[object]";
      }
    }
    return String(value);
  };

  if (typeof x !== "object" || x === null) {
    lines.push(`🔹 value: ${describeValue(x)}`);
    return lines.join("\n");
  }

  // Use both enumerable and non-enumerable properties
  const allProps = new Set<string>([
    ...Object.getOwnPropertyNames(x),
    ...Object.keys(x),
  ]);

  const proto = Object.getPrototypeOf(x);
  if (proto && proto !== Object.prototype) {
    lines.push(`🔹 Prototype: ${proto.constructor?.name ?? "[unknown]"}`);
  }

  for (const key of allProps) {
    try {
      const value = (x as any)[key];
      lines.push(`• ${key}: ${describeValue(value)}`);
    } catch (e) {
      lines.push(`• ${key}: [unreadable: ${(e as Error).message}]`);
    }
  }

  return lines.join("\n");
}

export const describeError = describeValue;

