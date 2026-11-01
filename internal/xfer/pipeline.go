package xfer

import "sync/atomic"

// Moving a file is a pipeline: on the sender, reading the file, hashing it
// and encrypting/sending run in parallel; on the receiver, receiving/
// decrypting, hashing and writing to disk do. Chunks flow through a fixed
// pool of buffers, each shared by two consumers (the hasher and the
// writer) and returned to the pool when both are done with it.

// pipelineDepth is how many chunks may be in flight per stage.
const pipelineDepth = 8

type chunk struct {
	data []byte // full buffer
	n    int    // valid bytes (after the frame header on the sender)
	refs atomic.Int32
	pool chan *chunk
}

// release returns c to its pool once every consumer has released it.
func (c *chunk) release() {
	if c.refs.Add(-1) == 0 {
		c.pool <- c
	}
}

func newChunkPool(size int) chan *chunk {
	pool := make(chan *chunk, 2*pipelineDepth)
	for range cap(pool) {
		pool <- &chunk{data: make([]byte, size), pool: pool}
	}
	return pool
}
