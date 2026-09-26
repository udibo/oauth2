export const CONCURRENT_CALLERS = 8;

export function race<T>(
  call: (caller: number) => Promise<T> | T,
): Promise<Awaited<T>[]> {
  return Promise.all(
    Array.from({ length: CONCURRENT_CALLERS }, (_, caller) => call(caller)),
  );
}
