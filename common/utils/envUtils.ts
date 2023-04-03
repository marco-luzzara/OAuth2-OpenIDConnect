import { exitIfEmpty } from "./validationUtils"
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import fs from 'fs'

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

/**
 * ClientInfo is used by the client and auth_server to use the last-registered client information
 * When a client is registered, its id and secret are stored in a file
 */
export class ClientInfo {
    readonly fileName: string
    private readonly readContentFn: () => Promise<string>
    private readonly writeContentFn: (data: string) => Promise<void>

    constructor(fileName: string) {
        this.fileName = fileName
        this.readContentFn = async () => await fs.promises.readFile(this.fileName, 'ascii')
        this.writeContentFn = async (data: string) => await fs.promises.writeFile(this.fileName, data, 'ascii')
    }

    public get clientId(): Promise<string> {
        return (async () => {
            const fileContent = await this.readContentFn()
            return fileContent.split('\n')[0]
        })()
    }

    public get clientSecret(): Promise<string> {
        return (async () => {
            const fileContent = await this.readContentFn()
            return fileContent.split('\n')[1]
        })()
    }

    public async writeClientInfo(clientId: string, clientSecret: string): Promise<void> {
        await this.writeContentFn(`${clientId}\n${clientSecret}`)
    }
}

