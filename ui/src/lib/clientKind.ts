/**
 * The kind of a client address worth a line under it in a table. The backend
 * classifies every address (backend-go/internal/sources/sources.go): an
 * internal address of the stack, a public address, or a private network
 * address. On a LAN every client is the last, so "Private network address"
 * under each row of the access log and the client list said nothing; it is
 * left out of the tables and kept in the details. An internal or a public
 * address is said, because it is not what a LAN client is expected to be.
 */
export const PRIVATE_KIND = 'Private network address';

export function tableKind(kind: string | null | undefined): string | undefined {
  if (!kind || kind === PRIVATE_KIND) return undefined;
  return kind;
}
