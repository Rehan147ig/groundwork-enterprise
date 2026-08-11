package spicedb

import "groundwork/query-runtime/internal/relationship/schema"

// Schema is the SpiceDB authorization model. The text itself lives in
// internal/relationship/schema/groundwork.zed — the single source of
// truth shared with the schema drift checks. See that package for the
// model description and semantics.
var Schema = schema.ZED()
