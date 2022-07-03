interface Hash {
  digest: () => Promise<Buffer>;
}
export interface UpdatableHash extends Hash {
  update: (value: string | Buffer) => UpdatableHash;
}

export enum HMAC {
  sha256 = 'sha256',
  sha512 = 'sha512',
}
