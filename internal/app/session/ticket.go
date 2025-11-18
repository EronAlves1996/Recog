package session

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/EronAlves1996/Recog/internal/app/base"
	"github.com/redis/go-redis/v9"
)

type retrieveSessionTicketAction struct {
	redisClient *redis.Client
}

func NewRetrieveTicketAction(redisClient redis.Client) *retrieveSessionTicketAction {
	return &retrieveSessionTicketAction{redisClient: &redisClient}
}

var _ base.Action[string, string] = retrieveSessionTicketAction{}

// Execute implements base.Action.
func (r retrieveSessionTicketAction) Execute(ctx context.Context, in *string) (*string, error) {
	cmd := r.redisClient.Get(ctx, *in)

	ticket, err := cmd.Bytes()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve key: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString(ticket)

	// Ticket retrieving only occur one time, gonna ignore this
	r.redisClient.Del(ctx, *in)

	return &encoded, nil
}
