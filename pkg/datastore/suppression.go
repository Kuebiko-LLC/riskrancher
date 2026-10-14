package datastore

import (
	"database/sql"
)

type GlobalSuppressionRule struct {
	MatchSource sql.NullString
	MatchAsset  sql.NullString
	MatchTitle  sql.NullString
	Rationale   string
}
