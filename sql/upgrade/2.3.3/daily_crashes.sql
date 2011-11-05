\set ON_ERROR_STOP 1

DROP FUNCTION backfill_daily_crashes( date, text );

CREATE OR REPLACE FUNCTION backfill_daily_crashes (
	updateday date )
RETURNS BOOLEAN
LANGUAGE plpgsql
SET work_mem = '512MB'
SET temp_buffers = '512MB'
AS $f$
DECLARE myproduct CITEXT := forproduct::citext;
BEGIN
-- VERSION 4
-- deletes and replaces daily_crashes for selected dates
-- now just nests a call to update_daily_crashes

DELETE FROM daily_crashes
WHERE adu_day = updateday;
PERFORM update_daily_crashes(updateday, false);

RETURN TRUE;

END;$f$;



CREATE OR REPLACE FUNCTION update_daily_crashes (
	updateday date, checkdata boolean default true )
RETURNS BOOLEAN
LANGUAGE plpgsql
SET work_mem = '512MB'
SET temp_buffers = '512MB'
AS $f$
BEGIN
-- update the daily crashes summary matview
-- VERSION 4
-- updates daily_crashes for new products using reports_clean
-- instead of using reports

-- apologies for badly written SQL, didn't want to rewrite it all from scratch

-- note: we are currently excluding crashes which are missing an OS_Name from the count

-- check if we've already been run
IF checkdata THEN
	PERFORM 1 FROM daily_crashes
	WHERE adu_day = updateday LIMIT 1;
	IF FOUND THEN
		RAISE EXCEPTION 'daily_crashes has already been run for %', updateday;
	END IF;
END IF;

-- check if reports_clean is updated
IF NOT reports_clean_done(updateday) THEN
	IF checkdata THEN
		RAISE EXCEPTION 'Reports_clean has not been updated to the end of %',updateday;
	ELSE
		RETURN TRUE;
	END IF;
END IF;

-- insert old browser crashes
-- for most crashes
INSERT INTO daily_crashes (count, report_type, productdims_id, os_short_name, adu_day)
SELECT COUNT(*) as count, daily_crash_code(process_type, hangid) as crash_code, p.id,
	substring(r.os_name, 1, 3) AS os_short_name,
	updateday
FROM product_visibility cfg
JOIN productdims p on cfg.productdims_id = p.id
JOIN reports r on p.product = r.product AND p.version = r.version
WHERE NOT cfg.ignore AND
	date_processed >= utc_day_begins_pacific(updateday)
		AND date_processed < utc_day_ends_pacific(updateday)
	AND updateday BETWEEN cfg.start_date and cfg.end_date
    AND lower(substring(os_name, 1, 3)) IN ('win','lin','mac')
    AND ( p.product = myproduct or myproduct = '' )
GROUP BY p.id, crash_code, os_short_name;

 -- insert HANGS_NORMALIZED from old data
INSERT INTO daily_crashes (count, report_type, productdims_id, os_short_name, adu_day)
SELECT count(subr.hangid) as count, 'H', subr.prod_id, subr.os_short_name,
	 updateday
FROM (
		   SELECT distinct hangid, p.id AS prod_id, substring(r.os_name, 1, 3) AS os_short_name
		   FROM product_visibility cfg
		   JOIN productdims p on cfg.productdims_id = p.id
		   JOIN reports r on p.product = r.product AND p.version = r.version
		   WHERE NOT cfg.ignore AND
				date_processed >= utc_day_begins_pacific(updateday)
					AND date_processed < utc_day_ends_pacific(updateday)
				AND updateday BETWEEN cfg.start_date and cfg.end_date
				AND hangid IS NOT NULL
                AND lower(substring(os_name, 1, 3)) IN ('win','lin','mac')
                AND ( p.product = myproduct or myproduct = '' )
		 ) AS subr
GROUP BY subr.prod_id, subr.os_short_name;

-- insert crash counts for new products
INSERT INTO daily_crashes (count, report_type, productdims_id, os_short_name, adu_day)
SELECT COUNT(*) as count, daily_crash_code(process_type, hang_id) as crash_code,
	product_version_id, 
	substring(os_name, 1, 3) AS os_short_name,
	updateday
FROM reports_clean JOIN product_versions USING (product_version_id)
WHERE utc_day_is(date_processed, updateday)
	AND updateday BETWEEN product_versions.build_date and sunset_date
    AND lower(substring(os_name, 1, 3)) IN ('win','lin','mac')
    AND ( product_name = myproduct or myproduct = '' )
GROUP BY product_version_id, crash_code, os_short_name;

-- insert normalized hangs for new products
INSERT INTO daily_crashes (count, report_type, productdims_id, os_short_name, adu_day)
SELECT count(DISTINCT subr.hang_id) as count, 'H', 
	product_version_id, substring(os_name, 1, 3) AS os_short_name,
	updateday
FROM product_versions
	JOIN reports_clean USING ( product_version_id )
	WHERE utc_day_is(date_processed, updateday)
		AND updateday BETWEEN product_versions.build_date and sunset_date
		AND ( product_name = myproduct or myproduct = '' )
		AND lower(substring(os_name, 1, 3)) IN ('win','lin','mac')
GROUP BY product_version_id, os_short_name;

ANALYZE daily_crashes;

RETURN TRUE;

END;$f$;

