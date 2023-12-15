package db

import (
	"context"

	"github.com/coinbase/baseca/internal/types"
	"github.com/google/uuid"
)

func (store *SQLStore) TxCreateServiceAccount(ctx context.Context, arg CreateServiceAccountParams, iid StoreInstanceIdentityDocumentParams) (*Account, error) {
	var serviceAccountResponse *Account

	err := store.execTx(ctx, func(q *Queries) error {
		var err error

		serviceAccountResponse, err = store.CreateServiceAccount(ctx, arg)
		if err != nil {
			return err
		}

		for _, node_attestation := range arg.NodeAttestation {
			switch node_attestation {
			case types.AWS_IID.String():
				// Add to AWS_IID Database
				_, err = store.StoreInstanceIdentityDocument(ctx, iid)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	return serviceAccountResponse, err
}

func (store *SQLStore) TxDeleteServiceAccount(ctx context.Context, client_id uuid.UUID) error {
	err := store.execTx(ctx, func(q *Queries) error {
		var err error

		err = store.DeleteInstanceIdentityDocument(ctx, client_id)
		if err != nil {
			return err
		}

		err = store.DeleteServiceAccount(ctx, client_id)
		if err != nil {
			return err
		}
		return err
	})
	return err
}
