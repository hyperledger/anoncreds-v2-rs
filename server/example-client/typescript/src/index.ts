export * from "./vcp";
export * from "VCP";

/**
 * The main module functionality
 */
export function sayHello(name: string = 'World'): string {
  return `Hello, ${name}!`;
}

export function getGreeting(name: string = 'World'): { message: string; timestamp: Date } {
  return {
    message: sayHello(name),
    timestamp: new Date()
  };
}
