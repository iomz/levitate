export type LogLevel = "debug" | "info" | "warn" | "error";

export interface Logger {
  debug(message: string, fields?: Record<string, unknown>): void;
  info(message: string, fields?: Record<string, unknown>): void;
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
}

const levelWeight: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export function createLogger(level: LogLevel = "info"): Logger {
  const minimum = levelWeight[level];

  const write = (
    severity: LogLevel,
    message: string,
    fields: Record<string, unknown> = {},
  ) => {
    if (levelWeight[severity] < minimum) return;

    const entry = {
      time: new Date().toISOString(),
      level: severity,
      message,
      ...fields,
    };
    process.stderr.write(`${JSON.stringify(entry)}\n`);
  };

  return {
    debug: (message, fields) => write("debug", message, fields),
    info: (message, fields) => write("info", message, fields),
    warn: (message, fields) => write("warn", message, fields),
    error: (message, fields) => write("error", message, fields),
  };
}
