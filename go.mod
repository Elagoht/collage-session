// A collage plugin for sessions kept in a cookie: a small map of strings, signed
// and optionally encrypted, with no store behind it. A request carrying one is
// rendered fresh, so one reader's page is never the cached page another is served.
//
// It requires collage the way any consumer does, and reaches nothing the framework
// does not offer every plugin.
module github.com/Elagoht/collage-session

go 1.26

require github.com/Elagoht/collage v0.29.0
