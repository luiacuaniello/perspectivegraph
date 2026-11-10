package api

import (
	"fmt"

	"github.com/graphql-go/graphql"
)

// schemaTypes holds the GraphQL types the schema's areas share. Each area builds its own
// and reads the ones it needs from the areas built before it.
type schemaTypes struct {
	nodeType                  *graphql.Object
	attackType                *graphql.Object
	edgeType                  *graphql.Object
	stepType                  *graphql.Object
	remediationEffectType     *graphql.Object
	cutEdgeType               *graphql.Object
	suggestionType            *graphql.Object
	detectionType             *graphql.Object
	fixType                   *graphql.Object
	suppressionType           *graphql.Object
	ticketType                *graphql.Object
	validationType            *graphql.Object
	profileScoreType          *graphql.Object
	pathType                  *graphql.Object
	violationType             *graphql.Object
	hitType                   *graphql.Object
	graphViewType             *graphql.Object
	prVerdictType             *graphql.Object
	postureType               *graphql.Object
	crownJewelRiskType        *graphql.Object
	profileCompromiseType     *graphql.Object
	riskSimulationType        *graphql.Object
	whatIfResultType          *graphql.Object
	statusType                *graphql.Object
	posturePointType          *graphql.Object
	historyType               *graphql.Object
	validationMetricsType     *graphql.Object
	reliabilityBinType        *graphql.Object
	calibrationSegmentType    *graphql.Object
	calibrationPointType      *graphql.Object
	basisRecalibrationType    *graphql.Object
	detectionStatsType        *graphql.Object
	discriminationType        *graphql.Object
	calibrationType           *graphql.Object
	ingestSourceType          *graphql.Object
	calibrationTrendPointType *graphql.Object
	labCheckType              *graphql.Object
	labRunType                *graphql.Object
	edgeCutInput              *graphql.InputObject
}

// Schema builds the GraphQL schema. Each area of it - the graph, the attack paths, the
// posture, the calibration - lives in a file of its own (schema_*.go): its types, then its
// queries. The types are built in the order they depend on each other; the queries are
// merged into the one Query type.
func (a *API) Schema() (graphql.Schema, error) {
	t := &schemaTypes{}
	a.graphTypes(t)
	a.remediationTypes(t)
	a.pathTypes(t)
	a.postureTypes(t)
	a.calibrationTypes(t)

	fields := graphql.Fields{}
	for _, area := range []graphql.Fields{a.estateQueries(t), a.pathQueries(t), a.postureQueries(t), a.calibrationQueries(t)} {
		for name, f := range area {
			if _, dup := fields[name]; dup {
				return graphql.Schema{}, fmt.Errorf("api: query %q is defined twice", name)
			}
			fields[name] = f
		}
	}
	query := graphql.NewObject(graphql.ObjectConfig{
		Name:   "Query",
		Fields: fields,
	})

	return graphql.NewSchema(graphql.SchemaConfig{Query: query})
}
