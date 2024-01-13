export interface SerializeUser<U, SU> {
  (user: U): Promise<SU | undefined>;
}

export interface DeserializeUser<U, SU> {
  (serialized: SU): Promise<U | undefined>;
}
