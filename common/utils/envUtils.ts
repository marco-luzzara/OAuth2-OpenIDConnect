import { exitIfEmpty } from "./validationUtils"
import { fileURLToPath } from 'url';
import { dirname } from 'path';

export default function dirName(meta: any): string {
    const __filename = fileURLToPath(meta.url);
    const __dirname = dirname(__filename);

    return __dirname;
}
export function getEnvOrExit(envName: string): string {
    const envVar = process.env[envName] || ''
    exitIfEmpty(envVar, `process.env.${envName}`)

    return envVar
}

