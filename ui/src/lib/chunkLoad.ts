/**
 * A lazy chunk that did not load: the message each browser gives for a
 * failed dynamic import (Chrome, Firefox, Safari), Vite's CSS preload
 * failure, or a webpack-style ChunkLoadError. A tab left open across an
 * upgrade asks for chunk names the new build no longer serves.
 */
const CHUNK_LOAD_ERROR = /dynamically imported module|Importing a module script failed|Unable to preload CSS|Loading chunk/;

export function isChunkLoadError(error: Error): boolean {
  return error.name === 'ChunkLoadError' || CHUNK_LOAD_ERROR.test(error.message);
}
