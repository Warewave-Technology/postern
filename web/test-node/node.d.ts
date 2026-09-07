/*
 * Node'un bu dizinde KULLANILAN parçalarının bildirimi.
 *
 * ⚠️ NİYE @types/node DEĞİL. Ölçüldü: paketi kurmak Node globallerini
 * (process, Buffer) TARAYICI kaynağına da açıyor — `types: []` bunu
 * kapatmıyor, çünkü src'deki test dosyaları vitest'i içe aktarıyor ve
 * vitest'in tipleri node'a referans veriyor. Sonuç, tarayıcıda var
 * olmayan bir şeyi kullanan kodun DERLENMESİ olurdu.
 *
 * Buradaki bildirimler yalnızca bu dizindeki testin BORU TESİSATI için;
 * ölçülen şey (SFTP çözümleyicisi) src'den geliyor ve gerçek bir
 * sftp-server'a karşı koşuyor. Bir bildirim yanlışsa test çalışırken
 * patlar — sessizce yanlış kalabileceği bir yer değil.
 */

declare module "node:child_process" {
  export interface ChildProcessWithoutNullStreams {
    stdin: { write(data: Uint8Array): boolean };
    stdout: { on(event: "data", cb: (chunk: Uint8Array) => void): void };
    on(event: "close", cb: () => void): void;
    kill(): boolean;
  }
  export function spawn(
    command: string,
    args: readonly string[],
    options: { stdio: readonly ["pipe", "pipe", "pipe"] },
  ): ChildProcessWithoutNullStreams;
}

declare module "node:fs" {
  export function existsSync(path: string): boolean;
  export function mkdtempSync(prefix: string): string;
  export function mkdirSync(path: string): void;
  export function writeFileSync(path: string, data: string | Uint8Array): void;
  export function readFileSync(path: string): Uint8Array;
  export function symlinkSync(target: string, path: string): void;
  export function rmSync(
    path: string,
    options: { recursive: boolean; force: boolean },
  ): void;
}

declare module "node:os" {
  export function tmpdir(): string;
}

declare module "node:path" {
  export function join(...parts: string[]): string;
}
