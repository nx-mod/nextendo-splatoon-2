package main

// Splatoon 2 DataStore (0x73) — stub.
//
// Splatoon 2 calls several DataStore methods during the online bring-up and pre-match
// phase. A full server-side DataStore implementation for these titles is not yet part of
// this tree, so every DataStore method is answered with an empty RMC success: the game
// proceeds through the bring-up, and the live log shows which methods it calls so they can
// be implemented properly over time.

import (
	"fmt"

	nex "github.com/NextendoNetwork/nextendo-nex"
)

// datastoreStubHandler answers every DataStore method with an empty success.
func datastoreStubHandler() nex.RMCHandler {
	return func(conn *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
		s := conn.Settings
		fmt.Printf("[S2 DataStore] 0x73.%d callID=%d -> empty success (stub)\n", req.Method, req.CallID)
		return nex.NewRMCSuccess(s, ProtocolDataStore, req.Method, req.CallID, nil)
	}
}

// setupS2DatastoreReplay registers the DataStore stub on the secure endpoint.
func setupS2DatastoreReplay(endpoint *nex.Endpoint) {
	endpoint.Register(ProtocolDataStore, datastoreStubHandler())
	fmt.Println("[S2 DataStore] stub registered (empty success for all methods)")
}
