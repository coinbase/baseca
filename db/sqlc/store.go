package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/coinbase/baseca/internal/types"
	"github.com/google/uuid"
)

type Store interface {
	Querier
	TxCreateServiceAccount(ctx context.Context, arg CreateServiceAccountParams, iid StoreInstanceIdentityDocumentParams) (*Account, error)
	TxDeleteServiceAccount(ctx context.Context, client_id uuid.UUID) error
	TxUpdateServiceAccount(ctx context.Context, arg Account, attestation types.NodeAttestation) (*Account, error)
	TxCreateProvisionerAccount(ctx context.Context, arg CreateProvisionerAccountParams, iid StoreInstanceIdentityDocumentParams) (*Provisioner, error)
	TxDeleteProvisionerAccount(ctx context.Context, client_id uuid.UUID) error
}
type SQLStore struct {
	db *sql.DB
	*Queries
}

func BuildDatastore(db *sql.DB) Store {
	return &SQLStore{
		db:      db,
		Queries: New(db),
	}
}

func BuildReadDatastore(db *sql.DB) Store {
	return &SQLStore{
		db:      db,
		Queries: New(db),
	}
}

func (store *SQLStore) execTx(ctx context.Context, fn func(*Queries) error) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	query := New(tx)
	err = fn(query)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("tx error: %v, rollback error: %v", err, rollbackErr)
		}
		return err
	}
	return tx.Commit()
}
