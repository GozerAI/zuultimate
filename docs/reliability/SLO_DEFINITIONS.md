# Identity Platform SLOs

## Authentication Availability
- **SLI:** % of auth requests returning 2xx or expected 4xx (excluding 5xx)
- **SLO:** 99.9% over 30-day rolling window
- **Error budget:** 43.2 minutes/month

## Authentication Latency
- **SLI:** % of auth requests completing in <500ms (p99)
- **SLO:** 95% of requests under 500ms
- **Measurement:** histogram, not average

## Token Introspection Availability
- **SLI:** % of introspect requests returning valid response
- **SLO:** 99.95%

## DSAR Response Time
- **SLI:** % of DSAR requests acknowledged within 24 hours
- **SLO:** 100% acknowledgment, 95% fulfilled within 30 days
