// retrieve_messages.go - client message retrieval
// Copyright (C) 2017  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package proxy provides mixnet client proxies
package proxy

import (
	"errors"
	"time"

	"github.com/katzenpost/client/scheduler"
	"github.com/katzenpost/client/session_pool"
	"github.com/katzenpost/core/wire/commands"
)

// Fetcher fetches messages for a given account identity
type Fetcher struct {
	Identity string
	sequence uint32
	pool     *session_pool.SessionPool
}

func NewFetcher(identity string, pool *session_pool.SessionPool) *Fetcher {
	fetcher := Fetcher{
		Identity: identity,
		sequence: uint32(0),
		pool:     pool,
	}
	return &fetcher
}

// Fetch fetches a message
func (f *Fetcher) Fetch() (uint8, error) {
	var queueHintSize uint8
	session, mutex, err := f.pool.Get(f.Identity)
	if err != nil {
		return uint8(0), err
	}
	mutex.Lock()
	defer mutex.Unlock()
	cmd := commands.RetrieveMessage{
		Sequence: f.sequence,
	}
	err = session.SendCommand(cmd)
	if err != nil {
		return uint8(0), err
	}
	recvCmd, err := session.RecvCommand()
	if err != nil {
		return uint8(0), err
	}
	if ack, ok := recvCmd.(commands.MessageACK); ok {
		log.Debug("retrieved MessageACK")
		queueHintSize = ack.QueueSizeHint
		err := f.processAck(&ack)
		if err != nil {
			return uint8(0), err
		}
	} else if message, ok := recvCmd.(commands.Message); ok {
		log.Debug("retrieved Message")
		queueHintSize = message.QueueSizeHint
		err := f.processMessage(&message)
		if err != nil {
			return uint8(0), err
		}
	} else {
		err := errors.New("retrieved non-Message/MessageACK wire protocol command")
		log.Debug(err)
		return uint8(0), err
	}
	f.sequence += 1
	return queueHintSize, nil
}

// processAck is used by our Stop and Wait ARQ to cancel
// the retransmit timer
func (f *Fetcher) processAck(ack *commands.MessageACK) error {

	return nil
}

// processMessage receives a message Block, decrypts it and
// writes it to our local bolt db for eventual processing.
func (f *Fetcher) processMessage(message *commands.Message) error {

	return nil
}

// FetchScheduler is scheduler which is used to periodically
// fetch messages using a set of fetchers
type FetchScheduler struct {
	fetchers map[string]*Fetcher
	sched    *scheduler.PriorityScheduler
	duration time.Duration
}

// NewFetchScheduler creates a new FetchScheduler
// given a slice of identity strings and a duration
func NewFetchScheduler(fetchers map[string]*Fetcher, duration time.Duration) *FetchScheduler {
	s := FetchScheduler{
		fetchers: fetchers,
		duration: duration,
	}
	s.sched = scheduler.New(s.handleFetch)
	return &s
}

// Start starts our periodic message checking scheduler
func (s *FetchScheduler) Start() {
	for _, fetcher := range s.fetchers {
		s.sched.Add(s.duration, fetcher.Identity)
	}
}

// handleFetch is called by the our scheduler when
// a fetch must be performed. After the fetch, we
// either schedule an immediate another fetch or a
// delayed fetch depending if there are more messages left.
// See "Panoramix Mix Network End-to-end Protocol Specification"
// https://github.com/Katzenpost/docs/blob/master/specs/end_to_end.txt
func (s *FetchScheduler) handleFetch(task interface{}) {
	identity, ok := task.(string)
	if !ok {
		log.Error("MessageRetriever got invalid task from priority scheduler.")
		return
	}
	fetcher, ok := s.fetchers[identity]
	if !ok {
		err := errors.New("fetcher identity not found")
		log.Error(err)
		return
	}
	queueSizeHint, err := fetcher.Fetch()
	if err != nil {
		log.Error(err)
		return
	}
	if queueSizeHint == 0 {
		s.sched.Add(s.duration, identity)
	} else {
		s.sched.Add(time.Duration(0), identity)
	}
	return
}
