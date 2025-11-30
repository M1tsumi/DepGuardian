import chalk from 'chalk';

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  SILENT = 4,
}

export class Logger {
  private level: LogLevel;

  constructor(level: LogLevel = LogLevel.INFO) {
    this.level = level;
  }

  setLevel(level: LogLevel): void {
    this.level = level;
  }

  debug(message: string, ...args: any[]): void {
    if (this.level <= LogLevel.DEBUG) {
      console.debug(chalk.gray(`[DEBUG] ${message}`), ...args);
    }
  }

  info(message: string, ...args: any[]): void {
    if (this.level <= LogLevel.INFO) {
      console.info(chalk.blue(`[INFO] ${message}`), ...args);
    }
  }

  warn(message: string, ...args: any[]): void {
    if (this.level <= LogLevel.WARN) {
      console.warn(chalk.yellow(`[WARN] ${message}`), ...args);
    }
  }

  error(message: string, ...args: any[]): void {
    if (this.level <= LogLevel.ERROR) {
      console.error(chalk.red(`[ERROR] ${message}`), ...args);
    }
  }

  success(message: string, ...args: any[]): void {
    if (this.level <= LogLevel.INFO) {
      console.info(chalk.green(`[SUCCESS] ${message}`), ...args);
    }
  }

  security(message: string, ...args: any[]): void {
    if (this.level <= LogLevel.WARN) {
      console.warn(chalk.magenta(`[SECURITY] ${message}`), ...args);
    }
  }

  vulnerability(message: string, severity: 'critical' | 'high' | 'medium' | 'low', ...args: any[]): void {
    if (this.level <= LogLevel.WARN) {
      let colorFn = chalk.white;
      
      switch (severity) {
        case 'critical':
          colorFn = chalk.red.bold;
          break;
        case 'high':
          colorFn = chalk.red;
          break;
        case 'medium':
          colorFn = chalk.yellow;
          break;
        case 'low':
          colorFn = chalk.blue;
          break;
      }

      console.warn(colorFn(`[${severity.toUpperCase()}] ${message}`), ...args);
    }
  }

  table(data: any[]): void {
    if (this.level <= LogLevel.INFO) {
      console.table(data);
    }
  }

  group(title: string, callback: () => void): void {
    if (this.level <= LogLevel.INFO) {
      console.group(chalk.cyan(title));
      callback();
      console.groupEnd();
    }
  }

  time(label: string): void {
    if (this.level <= LogLevel.DEBUG) {
      console.time(label);
    }
  }

  timeEnd(label: string): void {
    if (this.level <= LogLevel.DEBUG) {
      console.timeEnd(label);
    }
  }
}

export const logger = new Logger();
