\set ON_ERROR_STOP 1

SELECT backfill_matviews('2011-09-01');

SELECT backfill_reports_clean('2011-09-01');