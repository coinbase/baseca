package db

import (
	"context"

	"github.com/google/uuid"
)

func (store *SQLStore) TxCreateProvisionerAccount(ctx context.Context, arg CreateProvisionerAccountParams, iid StoreInstanceIdentityDocumentParams) (*Provisioner, error) {
	var provisionerAccountResponse *Provisioner

	err := store.execTx(ctx, func(q *Queries) error {
		var err error

		provisionerAccountResponse, err = store.CreateProvisionerAccount(ctx, arg)
		if err != nil {
			return err
		}

		for _, node_attestation := range arg.NodeAttestation {
			switch node_attestation {
			case "AWS_IID":
				// Add to AWS_IID Database
				_, err = store.StoreInstanceIdentityDocument(ctx, iid)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	return provisionerAccountResponse, err
}

func (store *SQLStore) TxDeleteProvisionerAccount(ctx context.Context, client_id uuid.UUID) error {
	err := store.execTx(ctx, func(q *Queries) error {
		var err error

		err = store.DeleteInstanceIdentityDocument(ctx, client_id)
		if err != nil {
			return err
		}

		err = store.DeleteProvisionerAccount(ctx, client_id)
		if err != nil {
			return err
		}
		return err
	})
	return err
}
