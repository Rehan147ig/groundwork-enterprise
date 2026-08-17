// Package sharepoint syncs SharePoint/OneDrive permissions into
// Groundwork.
//
// CONTRACT (Milestone 4): SharePoint permission semantics span
// inherited, sharing-link, site, library, folder, and item grants. This
// connector models site/library/folder/item grants plus folder→item
// inheritance; sharing links and anonymous/guest access are
// conservatively skipped (never granted). Graph delta handling is
// provided by the msgraph connector — prefer it for Microsoft 365
// tenants and treat this package as the standalone/on-prem path.
//
// Resources whose effective access depends on unmodeled semantics
// (sharing links, site policies, external sharing) are treated as
// denied (fail closed). The contract test suite
// (internal/aclsync/contract) is the gate for any change here.
package sharepoint
