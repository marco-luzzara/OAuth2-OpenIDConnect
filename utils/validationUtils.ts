import { exit } from 'process';

export function exit_if_empty(expression: string, name: string) {
    if (expression === '') {
        console.error(`${name} is undefined`)
        exit(1)
    }
}