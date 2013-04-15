/**************************************************************************
 *
 * AVAIL.C -  Icinga Availability CGI
 *
 * Copyright (c) 2000-2010 Ethan Galstad (egalstad@nagios.org)
 * Copyright (c) 2009-2012 Icinga Development Team (http://www.icinga.org)
 *
 * License:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *************************************************************************/

#include "../include/config.h"
#include "../include/common.h"
#include "../include/objects.h"
#include "../include/comments.h"
#include "../include/statusdata.h"
#include "../include/readlogs.h"

#include "../include/cgiutils.h"
#include "../include/cgiauth.h"
#include "../include/getcgi.h"


extern char main_config_file[MAX_FILENAME_LENGTH];
extern char url_html_path[MAX_FILENAME_LENGTH];
extern char url_images_path[MAX_FILENAME_LENGTH];
extern char url_stylesheets_path[MAX_FILENAME_LENGTH];
extern char url_js_path[MAX_FILENAME_LENGTH];

extern host      *host_list;
extern hostgroup *hostgroup_list;
extern servicegroup *servicegroup_list;
extern service   *service_list;
extern timeperiod *timeperiod_list;

extern int       log_rotation_method;

#ifndef max
#define max(a,b)  (((a) > (b)) ? (a) : (b))
#endif
#ifndef min
#define min(a,b)  (((a) < (b)) ? (a) : (b))
#endif

/* archived state types */
#define AS_CURRENT_STATE	-1   /* special case for initial assumed state */
#define AS_NO_DATA		0
#define AS_PROGRAM_END		1
#define AS_PROGRAM_START	2
#define AS_HOST_UP		3
#define AS_HOST_DOWN		4
#define AS_HOST_UNREACHABLE	5
#define AS_SVC_OK		6
#define AS_SVC_UNKNOWN		7
#define AS_SVC_WARNING		8
#define AS_SVC_CRITICAL		9

#define AS_SVC_DOWNTIME_START   10
#define AS_SVC_DOWNTIME_END     11
#define AS_HOST_DOWNTIME_START  12
#define AS_HOST_DOWNTIME_END    13

#define AS_SOFT_STATE           1
#define AS_HARD_STATE           2


/* display types */
#define DISPLAY_NO_AVAIL        0
#define DISPLAY_HOSTGROUP_AVAIL 1
#define DISPLAY_HOST_AVAIL      2
#define DISPLAY_SERVICE_AVAIL   3
#define DISPLAY_SERVICEGROUP_AVAIL 4

/* subject types */
#define HOST_SUBJECT            0
#define SERVICE_SUBJECT         1

#define MIN_TIMESTAMP_SPACING	10

#define MAX_ARCHIVE_SPREAD	65
#define MAX_ARCHIVE		65
#define MAX_ARCHIVE_BACKTRACKS	60

authdata current_authdata;

typedef struct archived_state_struct {
	time_t  time_stamp;
	int     entry_type;
	int     state_type;
	char    *state_info;
	int     processed_state;
	struct archived_state_struct *misc_ptr;
	struct archived_state_struct *next;
} archived_state;

typedef struct avail_subject_struct {
	int type;
	char *host_name;
	char *service_description;
	archived_state *as_list;        /* archived state list */
	archived_state *as_list_tail;
	archived_state *sd_list;        /* scheduled downtime list */
	int last_known_state;
	time_t earliest_time;
	time_t latest_time;
	int earliest_state;
	int latest_state;

	unsigned long time_up;
	unsigned long time_down;
	unsigned long time_unreachable;
	unsigned long time_ok;
	unsigned long time_warning;
	unsigned long time_unknown;
	unsigned long time_critical;

	unsigned long scheduled_time_up;
	unsigned long scheduled_time_down;
	unsigned long scheduled_time_unreachable;
	unsigned long scheduled_time_ok;
	unsigned long scheduled_time_warning;
	unsigned long scheduled_time_unknown;
	unsigned long scheduled_time_critical;
	unsigned long scheduled_time_indeterminate;

	unsigned long time_indeterminate_nodata;
	unsigned long time_indeterminate_notrunning;

	struct avail_subject_struct *next;
} avail_subject;

avail_subject *subject_list = NULL;

time_t t1;
time_t t2;

/* number of host (hheader) and service (sheader) titles */
#define		hheader_num	38
#define		sheader_num	49
char		*hheader[hheader_num];
char		*sheader[sheader_num];

int display_type = DISPLAY_NO_AVAIL;
int timeperiod_type = TIMEPERIOD_LAST24HOURS;
int show_log_entries = FALSE;
int full_log_entries = FALSE;
int show_scheduled_downtime = TRUE;

int start_second = 0;
int start_minute = 0;
int start_hour = 0;
int start_day = 1;
int start_month = 1;
int start_year = 2000;
int end_second = 0;
int end_minute = 0;
int end_hour = 24;
int end_day = 1;
int end_month = 1;
int end_year = 2000;

int get_date_parts = FALSE;
int select_hostgroups = FALSE;
int select_hosts = FALSE;
int select_servicegroups = FALSE;
int select_services = FALSE;

int compute_time_from_parts = FALSE;

int show_all_hostgroups = FALSE;
int show_all_hosts = FALSE;
int show_all_servicegroups = FALSE;
int show_all_services = FALSE;

int assume_initial_states = TRUE;
int assume_state_retention = TRUE;
int assume_states_during_notrunning = TRUE;
int initial_assumed_host_state = AS_NO_DATA;
int initial_assumed_service_state = AS_NO_DATA;
int include_soft_states = FALSE;

char *hostgroup_name = "";
char *host_name = "";
char *servicegroup_name = "";
char *service_desc = "";

void create_subject_list(void);
void add_subject(int, char *, char *);
avail_subject *find_subject(int, char *, char *);
void compute_availability(void);
void compute_subject_availability(avail_subject *, time_t);
void compute_subject_availability_times(int, int, time_t, time_t, time_t, avail_subject *, archived_state *);
void compute_subject_downtime(avail_subject *, time_t);
void compute_subject_downtime_times(time_t, time_t, avail_subject *, archived_state *);
void compute_subject_downtime_part_times(time_t, time_t, int, avail_subject *);
void display_hostgroup_availability(void);
void display_specific_hostgroup_availability(hostgroup *);
void display_servicegroup_availability(void);
void display_specific_servicegroup_availability(servicegroup *);
void display_host_availability(void);
void display_service_availability(void);
void write_log_entries(avail_subject *);

void get_running_average(double *, double, int);

void host_report_url(char *, char *);
void service_report_url(char *, char *, char *);
void compute_report_times(void);

int convert_host_state_to_archived_state(int);
int convert_service_state_to_archived_state(int);
void add_global_archived_state(int, int, time_t, char *);
void add_archived_state(int, int, time_t, char *, avail_subject *);
void add_scheduled_downtime(int, time_t, avail_subject *);
void free_availability_data(void);
void free_archived_state_list(archived_state *);
void read_archived_state_data(void);
unsigned long calculate_total_time(time_t, time_t);

int process_cgivars(void);

int backtrack_archives = 2;
int earliest_archive = 0;

extern int embedded;
extern int display_header;
extern int daemon_check;
extern int content_type;

extern char *csv_delimiter;
extern char *csv_data_enclosure;

timeperiod *current_timeperiod = NULL;

int CGI_ID = AVAIL_CGI_ID;

int main(int argc, char **argv) {
	int result = OK;
	char temp_buffer[MAX_INPUT_BUFFER];
	char start_timestring[MAX_DATETIME_LENGTH];
	char end_timestring[MAX_DATETIME_LENGTH];
	host *temp_host;
	service *temp_service;
	int is_authorized = TRUE;
	time_t report_start_time;
	time_t report_end_time;
	int days, hours, minutes, seconds;
	hostgroup *temp_hostgroup;
	servicegroup *temp_servicegroup;
	timeperiod *temp_timeperiod;
	time_t t3;
	time_t current_time;
	struct tm *t;

	/* reset internal CGI variables */
	reset_cgi_vars();

	/* read the CGI configuration file */
	result = read_cgi_config_file(get_cgi_config_location());
	if (result == ERROR) {
		document_header(CGI_ID, FALSE, "错误");
		print_error(get_cgi_config_location(), ERROR_CGI_CFG_FILE);
		document_footer(CGI_ID);
		return ERROR;
	}

	/* read the main configuration file */
	result = read_main_config_file(main_config_file);
	if (result == ERROR) {
		document_header(CGI_ID, FALSE, "错误");
		print_error(main_config_file, ERROR_CGI_MAIN_CFG);
		document_footer(CGI_ID);
		return ERROR;
	}

	/* read all object configuration data */
	result = read_all_object_configuration_data(main_config_file, READ_ALL_OBJECT_DATA);
	if (result == ERROR) {
		document_header(CGI_ID, FALSE, "错误");
		print_error(NULL, ERROR_CGI_OBJECT_DATA);
		document_footer(CGI_ID);
		return ERROR;
	}

	/* read all status data */
	result = read_all_status_data(get_cgi_config_location(), READ_ALL_STATUS_DATA);
	if (result == ERROR && daemon_check == TRUE) {
		document_header(CGI_ID, FALSE, "错误");
		print_error(NULL, ERROR_CGI_STATUS_DATA);
		document_footer(CGI_ID);
		return ERROR;
	}

	/* initialize time period to last 24 hours */
	time(&current_time);
	t2 = current_time;
	t1 = (time_t)(current_time - (60 * 60 * 24));

	/* default number of backtracked archives */
	switch (log_rotation_method) {
	case LOG_ROTATION_MONTHLY:
		backtrack_archives = 1;
		break;
	case LOG_ROTATION_WEEKLY:
		backtrack_archives = 2;
		break;
	case LOG_ROTATION_DAILY:
		backtrack_archives = 4;
		break;
	case LOG_ROTATION_HOURLY:
		backtrack_archives = 8;
		break;
	default:
		backtrack_archives = 2;
		break;
	}

	/* get the arguments passed in the URL */
	process_cgivars();

	document_header(CGI_ID, TRUE, "可用性");

	/* get authentication information */
	get_authentication_information(&current_authdata);


	if (compute_time_from_parts == TRUE)
		compute_report_times();

	/* make sure times are sane, otherwise swap them */
	if (t2 < t1) {
		t3 = t2;
		t2 = t1;
		t1 = t3;
	}

	/* don't let user create reports in the future */
	if (t2 > current_time) {
		t2 = current_time;
		if (t1 > t2)
			t1 = t2 - (60 * 60 * 24);
	}

	if (display_header == TRUE) {

		/* begin top table */
		printf("<table border=0 width=100%% cellspacing=0 cellpadding=0>\n");
		printf("<tr>\n");

		/* left column of the first row */
		printf("<td align=left valign=top width=33%%>\n");

		switch (display_type) {
		case DISPLAY_HOST_AVAIL:
			snprintf(temp_buffer, sizeof(temp_buffer) - 1, "主机可用性报告");
			break;
		case DISPLAY_SERVICE_AVAIL:
			snprintf(temp_buffer, sizeof(temp_buffer) - 1, "服务可用性报告");
			break;
		case DISPLAY_HOSTGROUP_AVAIL:
			snprintf(temp_buffer, sizeof(temp_buffer) - 1, "主机组可用性报告");
			break;
		case DISPLAY_SERVICEGROUP_AVAIL:
			snprintf(temp_buffer, sizeof(temp_buffer) - 1, "服务组可用性报告");
			break;
		default:
			snprintf(temp_buffer, sizeof(temp_buffer) - 1, "可用性报告");
			break;
		}
		temp_buffer[sizeof(temp_buffer)-1] = '\x0';
		display_info_table(temp_buffer, &current_authdata, daemon_check);

		if (((display_type == DISPLAY_HOST_AVAIL && show_all_hosts == FALSE) || (display_type == DISPLAY_SERVICE_AVAIL && show_all_services == FALSE)) && get_date_parts == FALSE) {

			printf("<TABLE BORDER=1 CELLPADDING=0 CELLSPACING=0 CLASS='linkBox'>\n");
			printf("<TR><TD CLASS='linkBox'>\n");

			if (display_type == DISPLAY_HOST_AVAIL && show_all_hosts == FALSE) {
				host_report_url("所有", "查看所有主机的可用性报");
				printf("<BR>\n");
#ifdef USE_TRENDS
				printf("<a href='%s?host=%s&t1=%lu&t2=%lu&assumestateretention=%s&assumeinitialstates=%s&includesoftstates=%s&assumestatesduringnotrunning=%s&initialassumedhoststate=%d&backtrack=%d'>查看该主机的趋势</a><BR>\n", TRENDS_CGI, url_encode(host_name), t1, t2, (include_soft_states == TRUE) ? "yes" : "no", (assume_state_retention == TRUE) ? "yes" : "no", (assume_initial_states == TRUE) ? "yes" : "no", (assume_states_during_notrunning == TRUE) ? "yes" : "no", initial_assumed_host_state, backtrack_archives);
#endif
#ifdef USE_HISTOGRAM
				printf("<a href='%s?host=%s&t1=%lu&t2=%lu&assumestateretention=%s'>查看该主机警告柱状图</a><BR>\n", HISTOGRAM_CGI, url_encode(host_name), t1, t2, (assume_state_retention == TRUE) ? "yes" : "no");
#endif
				printf("<a href='%s?type=%d&host=%s'>查看该主机信息</a><br>\n", EXTINFO_CGI, DISPLAY_HOST_INFO, url_encode(host_name));
				printf("<a href='%s?host=%s'>查看该主机服务状态详情</a><br>\n", STATUS_CGI, url_encode(host_name));
				printf("<a href='%s?host=%s'>查看该主机警告历史</a><br>\n", HISTORY_CGI, url_encode(host_name));
				printf("<a href='%s?host=%s'>查看该主机的通知信息</a><br>\n", NOTIFICATIONS_CGI, url_encode(host_name));
			} else if (display_type == DISPLAY_SERVICE_AVAIL && show_all_services == FALSE) {
				host_report_url(host_name, "查看该主机可用性报告");
				printf("<BR>\n");
				service_report_url("null", "所有", "查看所有服务可用性报告</b>");
				printf("<BR>\n");
#ifdef USE_TRENDS
				printf("<a href='%s?host=%s", TRENDS_CGI, url_encode(host_name));
				printf("&service=%s&t1=%lu&t2=%lu&assumestateretention=%s&includesoftstates=%s&assumeinitialstates=%s&assumestatesduringnotrunning=%s&initialassumedservicestate=%d&backtrack=%d'>查看该服务趋势</a><br>\n", url_encode(service_desc), t1, t2, (include_soft_states == TRUE) ? "yes" : "no", (assume_state_retention == TRUE) ? "yes" : "no", (assume_initial_states == TRUE) ? "yes" : "no", (assume_states_during_notrunning == TRUE) ? "yes" : "no", initial_assumed_service_state, backtrack_archives);
#endif
#ifdef USE_HISTOGRAM
				printf("<a href='%s?host=%s&service=%s&t1=%lu&t2=%lu&assumestateretention=%s'>查看该服务警告柱状图</a><br>\n", HISTOGRAM_CGI, url_encode(host_name), url_encode(service_desc), t1, t2, (assume_state_retention == TRUE) ? "yes" : "no");
#endif
				printf("<a href='%s?type=%d&host=%s&service=%s'>查看该服务信息<br>\n", EXTINFO_CGI, DISPLAY_SERVICE_INFO, url_encode(host_name), url_encode(service_desc));
				printf("<a href='%s?host=%s&service=%s'>查看该服务警告历史</a><br>\n", HISTORY_CGI, url_encode(host_name), url_encode(service_desc));
				printf("<a href='%s?host=%s&service=%s'>查看该服务通知信息<br>\n", NOTIFICATIONS_CGI, url_encode(host_name), url_encode(service_desc));
			}

			printf("</TD></TR>\n");
			printf("</TABLE>\n");
		}

		printf("</td>\n");

		/* center column of top row */
		printf("<td align=center valign=top width=33%%>\n");

		if (display_type != DISPLAY_NO_AVAIL && get_date_parts == FALSE) {

			/* find the host */
			temp_host = find_host(host_name);

			/* find the service */
			temp_service = find_service(host_name, service_desc);

			printf("<DIV ALIGN=CENTER CLASS='dataTitle'>\n");
			if (display_type == DISPLAY_HOST_AVAIL) {
				if (show_all_hosts == TRUE)
					printf("所有主机");
				else
					printf("主机'%s'", (temp_host != NULL && temp_host->display_name != NULL) ? temp_host->display_name : host_name);
			} else if (display_type == DISPLAY_SERVICE_AVAIL) {
				if (show_all_services == TRUE)
					printf("所有服务");
				else
						printf("主机'%s'上的'%s'服务", (temp_host != NULL && temp_host->display_name != NULL) ? temp_host->display_name : host_name, (temp_service != NULL && temp_service->display_name != NULL) ? temp_service->display_name : service_desc);
			} else if (display_type == DISPLAY_HOSTGROUP_AVAIL) {
				if (show_all_hostgroups == TRUE)
					printf("所有主机组");
				else
					printf("主机组'%s'", hostgroup_name);
			} else if (display_type == DISPLAY_SERVICEGROUP_AVAIL) {
				if (show_all_servicegroups == TRUE)
					printf("所有服务组");
				else
					printf("服务组'%s'", servicegroup_name);
			}
			printf("</DIV>\n");

			printf("<BR>\n");

			printf("<IMG SRC='%s%s' BORDER=0 ALT='可用性报告' TITLE='可用性报告'>\n", url_images_path, TRENDS_ICON);

			printf("<BR CLEAR=ALL>\n");

			get_time_string(&t1, start_timestring, sizeof(start_timestring) - 1, SHORT_DATE_TIME);
			get_time_string(&t2, end_timestring, sizeof(end_timestring) - 1, SHORT_DATE_TIME);
			printf("<div align=center class='reportRange'>%s 到 %s</div>\n", start_timestring, end_timestring);

			get_time_breakdown((time_t)(t2 - t1), &days, &hours, &minutes, &seconds);
			printf("<div align=center class='reportDuration'>持续时间: %02d天%02d时%02d分%02d秒</div>\n", days, hours, minutes, seconds);
		}

		printf("</td>\n");

		/* right hand column of top row */
		printf("<td align=right valign=bottom width=33%%>\n");

		printf("<form method=\"GET\" action=\"%s\">\n", AVAIL_CGI);
		printf("<table border=0 CLASS='optBox'>\n");

		if (display_type != DISPLAY_NO_AVAIL && get_date_parts == FALSE) {

			printf("<tr><td valign=top align=left class='optBoxItem'>首先假定%s状态:</td><td valign=top align=left class='optBoxItem'>%s</td></tr>\n", (display_type == DISPLAY_SERVICE_AVAIL) ? "服务" : "主机", (display_type == DISPLAY_HOST_AVAIL || display_type == DISPLAY_HOSTGROUP_AVAIL || display_type == DISPLAY_SERVICEGROUP_AVAIL) ? "首先假定服务的状态" : "");
			printf("<tr>\n");
			printf("<td valign=top align=left class='optBoxItem'>\n");

			printf("<input type='hidden' name='t1' value='%lu'>\n", (unsigned long)t1);
			printf("<input type='hidden' name='t2' value='%lu'>\n", (unsigned long)t2);
			if (show_log_entries == TRUE)
				printf("<input type='hidden' name='show_log_entries' value=''>\n");
			if (full_log_entries == TRUE)
				printf("<input type='hidden' name='full_log_entries' value=''>\n");
			if (display_type == DISPLAY_HOSTGROUP_AVAIL)
				printf("<input type='hidden' name='hostgroup' value='%s'>\n", escape_string(hostgroup_name));
			if (display_type == DISPLAY_HOST_AVAIL || display_type == DISPLAY_SERVICE_AVAIL)
				printf("<input type='hidden' name='host' value='%s'>\n", escape_string(host_name));
			if (display_type == DISPLAY_SERVICE_AVAIL)
				printf("<input type='hidden' name='service' value='%s'>\n", escape_string(service_desc));
			if (display_type == DISPLAY_SERVICEGROUP_AVAIL)
				printf("<input type='hidden' name='servicegroup' value='%s'>\n", escape_string(servicegroup_name));

			printf("<input type='hidden' name='assumeinitialstates' value='%s'>\n", (assume_initial_states == TRUE) ? "yes" : "no");
			printf("<input type='hidden' name='assumestateretention' value='%s'>\n", (assume_state_retention == TRUE) ? "yes" : "no");
			printf("<input type='hidden' name='assumestatesduringnotrunning' value='%s'>\n", (assume_states_during_notrunning == TRUE) ? "yes" : "no");
			printf("<input type='hidden' name='includesoftstates' value='%s'>\n", (include_soft_states == TRUE) ? "yes" : "no");

			if (display_type == DISPLAY_HOST_AVAIL || display_type == DISPLAY_HOSTGROUP_AVAIL || display_type == DISPLAY_SERVICEGROUP_AVAIL) {
				printf("<select name='initialassumedhoststate'>\n");
				printf("<option value=%d %s>未指定\n", AS_NO_DATA, (initial_assumed_host_state == AS_NO_DATA) ? "SELECTED" : "");
				printf("<option value=%d %s>当前状态\n", AS_CURRENT_STATE, (initial_assumed_host_state == AS_CURRENT_STATE) ? "SELECTED" : "");
				printf("<option value=%d %s>主机运行\n", AS_HOST_UP, (initial_assumed_host_state == AS_HOST_UP) ? "SELECTED" : "");
				printf("<option value=%d %s>主机宕机\n", AS_HOST_DOWN, (initial_assumed_host_state == AS_HOST_DOWN) ? "SELECTED" : "");
				printf("<option value=%d %s>主机不可达\n", AS_HOST_UNREACHABLE, (initial_assumed_host_state == AS_HOST_UNREACHABLE) ? "SELECTED" : "");
				printf("</select>\n");
			} else {
				printf("<input type='hidden' name='initialassumedhoststate' value='%d'>", initial_assumed_host_state);
				printf("<select name='initialassumedservicestate'>\n");
				printf("<option value=%d %s>未指定\n", AS_NO_DATA, (initial_assumed_service_state == AS_NO_DATA) ? "SELECTED" : "");
				printf("<option value=%d %s>当前状态\n", AS_CURRENT_STATE, (initial_assumed_service_state == AS_CURRENT_STATE) ? "SELECTED" : "");
				printf("<option value=%d %s>服务正常\n", AS_SVC_OK, (initial_assumed_service_state == AS_SVC_OK) ? "SELECTED" : "");
				printf("<option value=%d %s>服务警报\n", AS_SVC_WARNING, (initial_assumed_service_state == AS_SVC_WARNING) ? "SELECTED" : "");
				printf("<option value=%d %s>服务未知\n", AS_SVC_UNKNOWN, (initial_assumed_service_state == AS_SVC_UNKNOWN) ? "SELECTED" : "");
				printf("<option value=%d %s>服务严重\n", AS_SVC_CRITICAL, (initial_assumed_service_state == AS_SVC_CRITICAL) ? "SELECTED" : "");
				printf("</select>\n");
			}
			printf("</td>\n");
			printf("<td CLASS='optBoxItem'>\n");
			if (display_type == DISPLAY_HOST_AVAIL || display_type == DISPLAY_HOSTGROUP_AVAIL || display_type == DISPLAY_SERVICEGROUP_AVAIL) {
				printf("<select name='initialassumedservicestate'>\n");
				printf("<option value=%d %s>未指定\n", AS_NO_DATA, (initial_assumed_service_state == AS_NO_DATA) ? "SELECTED" : "");
				printf("<option value=%d %s>当前状态\n", AS_CURRENT_STATE, (initial_assumed_service_state == AS_CURRENT_STATE) ? "SELECTED" : "");
				printf("<option value=%d %s>服务正常\n", AS_SVC_OK, (initial_assumed_service_state == AS_SVC_OK) ? "SELECTED" : "");
				printf("<option value=%d %s>服务警报\n", AS_SVC_WARNING, (initial_assumed_service_state == AS_SVC_WARNING) ? "SELECTED" : "");
				printf("<option value=%d %s>服务未知\n", AS_SVC_UNKNOWN, (initial_assumed_service_state == AS_SVC_UNKNOWN) ? "SELECTED" : "");
				printf("<option value=%d %s>服务严重\n", AS_SVC_CRITICAL, (initial_assumed_service_state == AS_SVC_CRITICAL) ? "SELECTED" : "");
				printf("</select>\n");
			}
			printf("</td>\n");
			printf("</tr>\n");

			printf("<tr><td valign=top align=left class='optBoxItem'>报告周期:</td><td valign=top align=left class='optBoxItem'>存档回滚:</td></tr>\n");
			printf("<tr>\n");
			printf("<td valign=top align=left class='optBoxItem'>\n");
			printf("<select name='timeperiod'>\n");
			printf("<option SELECTED>[ 当前时间范围 ]\n");
			printf("<option value=today %s>今天\n", (timeperiod_type == TIMEPERIOD_TODAY) ? "SELECTED" : "");
			printf("<option value=last24hours %s>最近24小时\n", (timeperiod_type == TIMEPERIOD_LAST24HOURS) ? "SELECTED" : "");
			printf("<option value=yesterday %s>昨天\n", (timeperiod_type == TIMEPERIOD_YESTERDAY) ? "SELECTED" : "");
			printf("<option value=thisweek %s>本周\n", (timeperiod_type == TIMEPERIOD_THISWEEK) ? "SELECTED" : "");
			printf("<option value=last7days %s>最近7天\n", (timeperiod_type == TIMEPERIOD_LAST7DAYS) ? "SELECTED" : "");
			printf("<option value=lastweek %s>最近一周\n", (timeperiod_type == TIMEPERIOD_LASTWEEK) ? "SELECTED" : "");
			printf("<option value=thismonth %s>本月\n", (timeperiod_type == TIMEPERIOD_THISMONTH) ? "SELECTED" : "");
			printf("<option value=last31days %s>最近31天\n", (timeperiod_type == TIMEPERIOD_LAST31DAYS) ? "SELECTED" : "");
			printf("<option value=lastmonth %s>最近一月\n", (timeperiod_type == TIMEPERIOD_LASTMONTH) ? "SELECTED" : "");
			printf("<option value=thisyear %s>今年\n", (timeperiod_type == TIMEPERIOD_THISYEAR) ? "SELECTED" : "");
			printf("<option value=lastyear %s>去年\n", (timeperiod_type == TIMEPERIOD_LASTYEAR) ? "SELECTED" : "");
			printf("</select>\n");
			printf("</td>\n");
			printf("<td valign=top align=left CLASS='optBoxItem'>\n");
			printf("<input type='text' size='2' maxlength='2' name='backtrack' value='%d'>\n", backtrack_archives);
			printf("</td>\n");
			printf("</tr>\n");

			printf("<tr><td valign=top align=left></td>\n");
			printf("<td valign=top align=left CLASS='optBoxItem'>\n");
			printf("<input type='submit' value='更新'>\n");
			printf("</td>\n");
			printf("</tr>\n");
		}
		printf("</table>\n");
		printf("</form>\n");

		if (display_type == DISPLAY_NO_AVAIL || get_date_parts == TRUE)
			print_export_link(HTML_CONTENT, AVAIL_CGI, NULL);

		printf("</td>\n");

		/* end of top table */
		printf("</tr>\n");
		printf("</table>\n");
	}


	/* step 3 - ask user for report date range */
	if (get_date_parts == TRUE) {

		time(&current_time);
		t = localtime(&current_time);

		start_day = 1;
		start_year = t->tm_year + 1900;
		end_day = t->tm_mday;
		end_year = t->tm_year + 1900;

		printf("<DIV ALIGN=CENTER CLASS='dateSelectTitle'>步骤3: 选择报告选项</DIV>\n");

		printf("<form method=\"get\" action=\"%s\">\n", AVAIL_CGI);
		printf("<input type='hidden' name='show_log_entries' value=''>\n");
		if (display_type == DISPLAY_HOSTGROUP_AVAIL)
			printf("<input type='hidden' name='hostgroup' value='%s'>\n", escape_string(hostgroup_name));
		if (display_type == DISPLAY_HOST_AVAIL)
			printf("<input type='hidden' name='host' value='%s'>\n", escape_string(host_name));
		if (display_type == DISPLAY_SERVICE_AVAIL)
			printf("<input type='hidden' name='hostservice' value='%s^%s'>\n", escape_string(host_name), escape_string(service_desc));
		if (display_type == DISPLAY_SERVICEGROUP_AVAIL)
			printf("<input type='hidden' name='servicegroup' value='%s'>\n", escape_string(servicegroup_name));

		printf("<table border=0 cellpadding=5 align='center'>\n");

		printf("<tr>");
		printf("<td valign=top class='reportSelectSubTitle'>报告周期:</td>\n");
		printf("<td valign=top align=left class='optBoxItem'>\n");
		printf("<select name='timeperiod'>\n");
		printf("<option value=today>今天\n");
		printf("<option value=last24hours>最近24小时\n");
		printf("<option value=yesterday>昨天\n");
		printf("<option value=thisweek>本周\n");
		printf("<option value=last7days SELECTED>最近7天\n");
		printf("<option value=lastweek>最近一周\n");
		printf("<option value=thismonth>本月\n");
		printf("<option value=last31days>最近31天\n");
		printf("<option value=lastmonth>最近一月\n");
		printf("<option value=thisyear>今年\n");
		printf("<option value=lastyear>去年\n");
		printf("<option value=custom>* 自定义报告周期 *\n");
		printf("</select>\n");
		printf("</td>\n");
		printf("</tr>\n");

		printf("<tr><td valign=top class='reportSelectSubTitle'>如果自定义报告周期...</td></tr>\n");

		printf("<tr>");
		printf("<td valign=top class='reportSelectSubTitle'>开始日期(含):</td>\n");
		printf("<td align=left valign=top class='reportSelectItem'>");
		printf("<select name='smon'>\n");
		printf("<option value='1' %s>一月\n",(t->tm_mon==0)?"SELECTED":"");
		printf("<option value='2' %s>二月\n",(t->tm_mon==1)?"SELECTED":"");
		printf("<option value='3' %s>三月\n",(t->tm_mon==2)?"SELECTED":"");
		printf("<option value='4' %s>四月\n",(t->tm_mon==3)?"SELECTED":"");
		printf("<option value='5' %s>五月\n",(t->tm_mon==4)?"SELECTED":"");
		printf("<option value='6' %s>六月\n",(t->tm_mon==5)?"SELECTED":"");
		printf("<option value='7' %s>七月\n",(t->tm_mon==6)?"SELECTED":"");
		printf("<option value='8' %s>八月\n",(t->tm_mon==7)?"SELECTED":"");
		printf("<option value='9' %s>九月\n",(t->tm_mon==8)?"SELECTED":"");
		printf("<option value='10' %s>十月\n",(t->tm_mon==9)?"SELECTED":"");
		printf("<option value='11' %s>十一月\n",(t->tm_mon==10)?"SELECTED":"");
		printf("<option value='12' %s>十二月\n",(t->tm_mon==11)?"SELECTED":"");
		printf("</select>\n ");
		printf("<input type='text' size='2' maxlength='2' name='sday' value='%d'> ", start_day);
		printf("<input type='text' size='4' maxlength='4' name='syear' value='%d'>", start_year);
		printf("<input type='hidden' name='shour' value='0'>\n");
		printf("<input type='hidden' name='smin' value='0'>\n");
		printf("<input type='hidden' name='ssec' value='0'>\n");
		printf("</td>\n");
		printf("</tr>\n");

		printf("<tr>");
		printf("<td valign=top class='reportSelectSubTitle'>结束日期(含):</td>\n");
		printf("<td align=left valign=top class='reportSelectItem'>");
		printf("<select name='emon'>\n");
		printf("<option value='1' %s>一月\n",(t->tm_mon==0)?"SELECTED":"");
		printf("<option value='2' %s>二月\n",(t->tm_mon==1)?"SELECTED":"");
		printf("<option value='3' %s>三月\n",(t->tm_mon==2)?"SELECTED":"");
		printf("<option value='4' %s>四月\n",(t->tm_mon==3)?"SELECTED":"");
		printf("<option value='5' %s>五月\n",(t->tm_mon==4)?"SELECTED":"");
		printf("<option value='6' %s>六月\n",(t->tm_mon==5)?"SELECTED":"");
		printf("<option value='7' %s>七月\n",(t->tm_mon==6)?"SELECTED":"");
		printf("<option value='8' %s>八月\n",(t->tm_mon==7)?"SELECTED":"");
		printf("<option value='9' %s>九月\n",(t->tm_mon==8)?"SELECTED":"");
		printf("<option value='10' %s>十月\n",(t->tm_mon==9)?"SELECTED":"");
		printf("<option value='11' %s>十一月\n",(t->tm_mon==10)?"SELECTED":"");
		printf("<option value='12' %s>十二月\n",(t->tm_mon==11)?"SELECTED":"");
		printf("</select>\n ");
		printf("<input type='text' size='2' maxlength='2' name='eday' value='%d'> ", end_day);
		printf("<input type='text' size='4' maxlength='4' name='eyear' value='%d'>", end_year);
		printf("<input type='hidden' name='ehour' value='24'>\n");
		printf("<input type='hidden' name='emin' value='0'>\n");
		printf("<input type='hidden' name='esec' value='0'>\n");
		printf("</td>\n");
		printf("</tr>\n");

		printf("<tr><td colspan=2><br></td></tr>\n");

		printf("<tr>");
		printf("<td valign=top class='reportSelectSubTitle'>报告时间周期:</td>\n");
		printf("<td valign=top align=left class='optBoxItem'>\n");
		printf("<select name='rpttimeperiod'>\n");
		printf("<option value=\"\">无\n");
		/* check all the time periods... */
		for (temp_timeperiod = timeperiod_list; temp_timeperiod != NULL; temp_timeperiod = temp_timeperiod->next)
			printf("<option value=%s>%s\n", escape_string(temp_timeperiod->name), temp_timeperiod->name);
		printf("</select>\n");
		printf("</td>\n");
		printf("</tr>\n");
		printf("<tr><td colspan=2><br></td></tr>\n");

		printf("<tr><td class='reportSelectSubTitle' align=right>假定初始状态:</td>\n");
		printf("<td class='reportSelectItem'>\n");
		printf("<select name='assumeinitialstates'>\n");
		printf("<option value=yes>是\n");
		printf("<option value=no>否\n");
		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr><td class='reportSelectSubTitle' align=right>假定状态保持:</td>\n");
		printf("<td class='reportSelectItem'>\n");
		printf("<select name='assumestateretention'>\n");
		printf("<option value=yes>是\n");
		printf("<option value=no>否\n");
		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr><td class='reportSelectSubTitle' align=right>假定程序宕机期间状态:</td>\n");
		printf("<td class='reportSelectItem'>\n");
		printf("<select name='assumestatesduringnotrunning'>\n");
		printf("<option value=yes>是\n");
		printf("<option value=no>否\n");
		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr><td class='reportSelectSubTitle' align=right>包括软件状态:</td>\n");
		printf("<td class='reportSelectItem'>\n");
		printf("<select name='includesoftstates'>\n");
		printf("<option value=yes>是\n");
		printf("<option value=no SELECTED>否\n");
		printf("</select>\n");
		printf("</td></tr>\n");

		if (display_type != DISPLAY_SERVICE_AVAIL) {
			printf("<tr><td class='reportSelectSubTitle' align=right>首先假定主机的状态:</td>\n");
			printf("<td class='reportSelectItem'>\n");
			printf("<select name='initialassumedhoststate'>\n");
			printf("<option value=%d>未指定\n", AS_NO_DATA);
			printf("<option value=%d>当前状态\n", AS_CURRENT_STATE);
			printf("<option value=%d>主机运行\n", AS_HOST_UP);
			printf("<option value=%d>主机宕机\n", AS_HOST_DOWN);
			printf("<option value=%d>主机不可达\n", AS_HOST_UNREACHABLE);
			printf("</select>\n");
			printf("</td></tr>\n");
		}

		printf("<tr><td class='reportSelectSubTitle' align=right>首先假定的服务状态:</td>\n");
		printf("<td class='reportSelectItem'>\n");
		printf("<select name='initialassumedservicestate'>\n");
		printf("<option value=%d>未指定\n", AS_NO_DATA);
		printf("<option value=%d>当前状态\n", AS_CURRENT_STATE);
		printf("<option value=%d>服务正常\n", AS_SVC_OK);
		printf("<option value=%d>服务警报\n", AS_SVC_WARNING);
		printf("<option value=%d>服务未知\n", AS_SVC_UNKNOWN);
		printf("<option value=%d>服务严重\n", AS_SVC_CRITICAL);
		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr><td class='reportSelectSubTitle' align=right>存档回滚(用于扫描初始状态):</td>\n");
		printf("<td class='reportSelectItem'>\n");
		printf("<input type='text' name='backtrack' size='2' maxlength='2' value='%d'>\n", backtrack_archives);
		printf("</td></tr>\n");

		/* CSV Output is available in all selections */
		printf("<tr>");
		printf("<td valign=top class='reportSelectSubTitle' style='vertical-align:middle'>输出格式:</td>\n");
		printf("<td valign=top class='reportSelectItem'>");
		printf("<DIV><input type='radio' name='content_type' value='html' checked> HTML</DIV>\n");
		printf("<DIV><input type='radio' name='content_type' value='csv'> CSV</DIV>\n");
		printf("<DIV><input type='radio' name='content_type' value='json'> JSON</DIV>\n");
		printf("<DIV><input type='radio' name='content_type' value='xml'> XML</DIV>\n");
		printf("</td>\n");
		printf("</tr>\n");

		printf("<tr><td></td><td align=left class='dateSelectItem'><input type='submit' value='生成可用性报告!'></td></tr>\n");

		printf("</table>\n");

		printf("</form>\n");
	}


	/* step 2 - the user wants to select a hostgroup */
	else if (select_hostgroups == TRUE) {
		printf("<div align=center class='reportSelectTitle'>步骤２: 选择主机组</div>\n");

		printf("<form method=\"get\" action=\"%s\">\n", AVAIL_CGI);
		printf("<input type='hidden' name='get_date_parts'>\n");

		printf("<table border=0 cellpadding=5 align='center'>\n");

		printf("<tr><td class='reportSelectSubTitle' valign=center>主机组:</td><td align=left valign=center class='reportSelectItem'>\n");
		printf("<select name='hostgroup'>\n");
		printf("<option value='all'>** 所有主机组 **\n");
		for (temp_hostgroup = hostgroup_list; temp_hostgroup != NULL; temp_hostgroup = temp_hostgroup->next) {
			if (is_authorized_for_hostgroup(temp_hostgroup, &current_authdata) == TRUE)
				printf("<option value='%s'>%s\n", escape_string(temp_hostgroup->group_name), temp_hostgroup->group_name);
		}
		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr><td></td><td align=left class='dateSelectItem'><input type='submit' value='步骤３续'></td></tr>\n");

		printf("</table>\n");

		printf("</form>\n");
	}

	/* step 2 - the user wants to select a host */
	else if (select_hosts == TRUE) {
		printf("<div align=center class='reportSelectTitle'>步骤２: 选择主机</div>\n");

		printf("<form method=\"get\" action=\"%s\">\n", AVAIL_CGI);
		printf("<input type='hidden' name='get_date_parts'>\n");

		printf("<table border=0 cellpadding=5 align='center'>\n");

		printf("<tr><td class='reportSelectSubTitle' valign=center>主机:</td><td align=left valign=center class='reportSelectItem'>\n");
		printf("<select name='host'>\n");
		printf("<option value='all'>** 所有主机 **\n");
		for (temp_host = host_list; temp_host != NULL; temp_host = temp_host->next) {
			if (is_authorized_for_host(temp_host, &current_authdata) == TRUE)
				printf("<option value='%s'>%s\n", escape_string(temp_host->name), (temp_host->display_name != NULL) ? temp_host->display_name : temp_host->name);
		}
		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr><td></td><td align=left class='dateSelectItem'><input type='submit' value='步骤３续'></td></tr>\n");

		printf("</table>\n");

		printf("</form>\n");
	}

	/* step 2 - the user wants to select a servicegroup */
	else if (select_servicegroups == TRUE) {
		printf("<div align=center class='reportSelectTitle'>步骤２: 选择服务组</div>\n");

		printf("<form method=\"get\" action=\"%s\">\n", AVAIL_CGI);
		printf("<input type='hidden' name='get_date_parts'>\n");

		printf("<table border=0 cellpadding=5 align='center'>\n");

		printf("<tr><td class='reportSelectSubTitle' valign=center>Servicegroup(s):</td><td align=left valign=center class='reportSelectItem'>\n");
		printf("<select name='servicegroup'>\n");
		printf("<option value='all'>** 所有服务组 **\n");
		for (temp_servicegroup = servicegroup_list; temp_servicegroup != NULL; temp_servicegroup = temp_servicegroup->next) {
			if (is_authorized_for_servicegroup(temp_servicegroup, &current_authdata) == TRUE)
				printf("<option value='%s'>%s\n", escape_string(temp_servicegroup->group_name), temp_servicegroup->group_name);
		}
		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr><td></td><td align=left class='dateSelectItem'><input type='submit' value='步骤３续'></td></tr>\n");

		printf("</table>\n");

		printf("</form>\n");
	}

	/* step 2 - the user wants to select a service */
	else if (select_services == TRUE) {

		printf("<div align=center class='reportSelectTitle'>步骤２: 选择服务</div>\n");

		printf("<form method=\"post\" action=\"%s\" name='serviceform'>\n", AVAIL_CGI);
		printf("<input type='hidden' name='get_date_parts'>\n");

		printf("<table border=0 cellpadding=5 align='center'>\n");

		printf("<tr><td class='reportSelectSubTitle' valign=center>服务:</td><td align=left valign=center class='reportSelectItem'>\n");
		printf("<select name='hostservice' >\n");
		printf("<option value='all^all'>** 所有服务 **\n");
		for (temp_service = service_list; temp_service != NULL; temp_service = temp_service->next) {
			if (is_authorized_for_service(temp_service, &current_authdata) == TRUE)
				printf("<option value='%s^%s'>%s;%s\n", escape_string(temp_service->host_name), escape_string(temp_service->description), temp_service->host_name, (temp_service->display_name != NULL) ? temp_service->display_name : temp_service->description);
		}

		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr><td></td><td align=left class='dateSelectItem'><input type='submit' value='步骤３续'></td></tr>\n");

		printf("</table>\n");

		printf("</form>\n");
	}


	/* generate availability report */
	else if (display_type != DISPLAY_NO_AVAIL) {

		/* check authorization */
		is_authorized = TRUE;
		if ((display_type == DISPLAY_HOST_AVAIL && show_all_hosts == FALSE) || (display_type == DISPLAY_SERVICE_AVAIL && show_all_services == FALSE)) {

			if (display_type == DISPLAY_HOST_AVAIL && show_all_hosts == FALSE)
				is_authorized = is_authorized_for_host(find_host(host_name), &current_authdata);
			else
				is_authorized = is_authorized_for_service(find_service(host_name, service_desc), &current_authdata);
		}

		if (is_authorized == FALSE) {
			if (display_type == DISPLAY_HOST_AVAIL)
				print_generic_error_message("很显然您未被授权查看指定主机的信息...", NULL, 0);
			else
				print_generic_error_message("很显然您未被授权查看指定服务的信息...", NULL, 0);

		} else {

			time(&report_start_time);

			/* create list of subjects to collect availability data for */
			create_subject_list();

			/* read in all necessary archived state data */
			read_archived_state_data();

			/* compute availability data */
			compute_availability();

			time(&report_end_time);

			if (content_type == HTML_CONTENT) {
				get_time_breakdown((time_t)(report_end_time - report_start_time), &days, &hours, &minutes, &seconds);
				printf("<div align=center class='reportTime'>[ 可用性报告完成用时 %02d分%02d秒 ]</div>\n", minutes, seconds);

				/* add export to csv, json, xml, link */
				printf("<div class='csv_export_link' align=right>");
				print_export_link(CSV_CONTENT, AVAIL_CGI, NULL);
				print_export_link(JSON_CONTENT, AVAIL_CGI, NULL);
				print_export_link(XML_CONTENT, AVAIL_CGI, NULL);
				print_export_link(HTML_CONTENT, AVAIL_CGI, NULL);
				printf("</div>\n");

				printf("<BR><BR>\n");
			}

			/* devine host header for non HTML output */
			hheader[0] = "主机名称";
			hheader[37] = "主机显示名称";

			/* up times */
			hheader[1] = "安排运行时间";
			hheader[2] = "安排运行时间百分比";
			hheader[3] = "安排已知运行时间百分比";
			hheader[4] = "未安排运行时间";
			hheader[5] = "未安排运行时间百分比";
			hheader[6] = "未安排已知运行时间百分比";
			hheader[7] = "总计运行时间";
			hheader[8] = "总计运行时间百分比";
			hheader[9] = "已知运行时间百分比";

			/* down times */
			hheader[10] = "安排宕机时间";
			hheader[11] = "安排宕机时间百分比";
			hheader[12] = "安排已知宕机时间百分比";
			hheader[13] = "未安排宕机时间";
			hheader[14] = "未安排宕机时间百分比";
			hheader[15] = "未安排已知宕机时间百分比";
			hheader[16] = "总计宕机时间";
			hheader[17] = "总计宕机时间百分比";
			hheader[18] = "已知宕机时间百分比";

			/* unreachable times */
			hheader[19] = "安排不可达时间";
			hheader[20] = "安排不可达时间百分比";
			hheader[21] = "安排已知不可达时间百分比";
			hheader[22] = "未安排不可达时间";
			hheader[23] = "未安排不可达时间百分比";
			hheader[24] = "未安排已知不可达时间百分比";
			hheader[25] = "总计不可达时间";
			hheader[26] = "总计不可达时间百分比";
			hheader[27] = "已知不可达时间百分比";

			/* undeterminate times */
			hheader[28] = "不运行未决时间";
			hheader[29] = "不运行未决时间百分比";
			hheader[30] = "无数据未决时间";
			hheader[31] = "无数据未决时间百分比";
			hheader[32] = "总计未决时间";
			hheader[33] = "总计未决时间百分比";

			/* total times for single host view */
			hheader[34] = "总计所有时间";
			hheader[35] = "总计所有时间百分比";
			hheader[36] = "已知所有时间百分比";


			/* devine service header for non HTML output */
			sheader[0] = "主机名称";
			sheader[47] = "主机显示名称";
			sheader[1] = "服务描述";
			sheader[48] = "服务显示名称";

			/* ok times */
			sheader[2] = "安排正常时间";
			sheader[3] = "安排正常时间百分比";
			sheader[4] = "已知正常时间百分比";
			sheader[5] = "未安排正常时间";
			sheader[6] = "未安排正常时间百分比";
			sheader[7] = "未安排已知正常时间百分比";
			sheader[8] = "总计正常时间";
			sheader[9] = "总计正常时间百分比";
			sheader[10] = "已知正常时间百分比";

			/* warning times */
			sheader[11] = "安排警报时间";
			sheader[12] = "安排警报时间百分比";
			sheader[13] = "安排已知警报时间百分比";
			sheader[14] = "未安排警报时间";
			sheader[15] = "未安排警报时间百分比";
			sheader[16] = "未安排已知警报时间百分比";
			sheader[17] = "总计警报时间";
			sheader[18] = "总计警报时间百分比";
			sheader[19] = "已知警报时间百分比";

			/* unknown times */
			sheader[20] = "安排未知时间";
			sheader[21] = "安排未知时间百分比";
			sheader[22] = "安排已知未知时间百分比";
			sheader[23] = "未安排未知时间";
			sheader[24] = "未安排未知时间百分比";
			sheader[25] = "未安排已知未知时间百分比";
			sheader[26] = "总计未知时间";
			sheader[27] = "总计未知时间百分比";
			sheader[28] = "已知未知时间百分比";

			/* critical times */
			sheader[29] = "安排严重时间";
			sheader[30] = "安排严重时间百分比";
			sheader[31] = "安排已知严重时间百分比";
			sheader[32] = "未安排严重时间";
			sheader[33] = "未安排严重时间百分比";
			sheader[34] = "未安排已知严重时间百分比";
			sheader[35] = "总计严重时间";
			sheader[36] = "总计严重时间百分比";
			sheader[37] = "已知严重时间百分比";

			/* undeterminate times */
			sheader[38] = "不运行决时间";
			sheader[39] = "不运行未决时间百分比";
			sheader[40] = "无数据未决时间";
			sheader[41] = "无数据未决时间百分比";
			sheader[42] = "总计未决时间";
			sheader[43] = "总计未决时间百分比";

			/* total times for single service view */
			sheader[44] = "总计所有时间";
			sheader[45] = "总计所有时间百分比";
			sheader[46] = "已知所有时间百分比";


			/* display availability data */
			if (display_type == DISPLAY_HOST_AVAIL)
				display_host_availability();
			else if (display_type == DISPLAY_SERVICE_AVAIL)
				display_service_availability();
			else if (display_type == DISPLAY_HOSTGROUP_AVAIL)
				display_hostgroup_availability();
			else if (display_type == DISPLAY_SERVICEGROUP_AVAIL)
				display_servicegroup_availability();

			/* free memory allocated to availability data */
			free_availability_data();
		}
	}


	/* step 1 - ask the user what kind of report they want */
	else {

		printf("<div align=center class='reportSelectTitle'>步骤１: 选择报告类型</div>\n");

		printf("<form method=\"get\" action=\"%s\">\n", AVAIL_CGI);

		printf("<table border=0 cellpadding=5 align='center'>\n");

		printf("<tr><td class='reportSelectSubTitle' align=right>类型:</td>\n");
		printf("<td class='reportSelectItem'>\n");
		printf("<select name='report_type'>\n");
		printf("<option value=hostgroups>主机组\n");
		printf("<option value=hosts>主机\n");
		printf("<option value=servicegroups>服务组\n");
		printf("<option value=services>服务\n");
		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr><td></td><td align=left class='dateSelectItem'><input type='submit' value='步骤２续'></td></tr>\n");

		printf("</table>\n");

		printf("</form>\n");
	}


	document_footer(CGI_ID);

	/* free all other allocated memory */
	free_memory();

	return OK;
}

int process_cgivars(void) {
	char **variables;
	char *temp_buffer = NULL;
	int error = FALSE;
	int x;

	variables = getcgivars();

	for (x = 0; variables[x] != NULL; x++) {

		/* do some basic length checking on the variable identifier to prevent buffer overflows */
		if (strlen(variables[x]) >= MAX_INPUT_BUFFER - 1) {
			x++;
			continue;
		}

		/* we found the hostgroup argument */
		else if (!strcmp(variables[x], "hostgroup")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if ((hostgroup_name = (char *)strdup(variables[x])) == NULL)
				hostgroup_name = "";
			strip_html_brackets(hostgroup_name);

			display_type = DISPLAY_HOSTGROUP_AVAIL;
			show_all_hostgroups = (strcmp(hostgroup_name, "all")) ? FALSE : TRUE;
		}

		/* we found the servicegroup argument */
		else if (!strcmp(variables[x], "servicegroup")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if ((servicegroup_name = (char *)strdup(variables[x])) == NULL)
				servicegroup_name = "";
			strip_html_brackets(servicegroup_name);

			display_type = DISPLAY_SERVICEGROUP_AVAIL;
			show_all_servicegroups = (strcmp(servicegroup_name, "all")) ? FALSE : TRUE;
		}

		/* we found the host argument */
		else if (!strcmp(variables[x], "host")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if ((host_name = (char *)strdup(variables[x])) == NULL)
				host_name = "";
			strip_html_brackets(host_name);

			/* only switch to host view if no service is submitted */
			if (strlen(service_desc) == 0)
				display_type = DISPLAY_HOST_AVAIL;
			show_all_hosts = (strcmp(host_name, "all")) ? FALSE : TRUE;
		}

		/* we found the service description argument */
		else if (!strcmp(variables[x], "service")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if ((service_desc = (char *)strdup(variables[x])) == NULL)
				service_desc = "";
			strip_html_brackets(service_desc);

			display_type = DISPLAY_SERVICE_AVAIL;
			show_all_services = (strcmp(service_desc, "all")) ? FALSE : TRUE;
		}

		/* we found a combined host/service */
		else if (!strcmp(variables[x], "hostservice")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			temp_buffer = strtok(variables[x], "^");

			if ((host_name = (char *)strdup(temp_buffer)) == NULL)
				host_name = "";
			else
				strip_html_brackets(host_name);

			temp_buffer = strtok(NULL, "");

			if ((service_desc = (char *)strdup(temp_buffer)) == NULL)
				service_desc = "";
			else
				strip_html_brackets(service_desc);

			display_type = DISPLAY_SERVICE_AVAIL;
			show_all_services = (strcmp(service_desc, "all")) ? FALSE : TRUE;
		}

		/* we found first time argument */
		else if (!strcmp(variables[x], "t1")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			t1 = (time_t)strtoul(variables[x], NULL, 10);
			timeperiod_type = TIMEPERIOD_CUSTOM;
			compute_time_from_parts = FALSE;
		}

		/* we found first time argument */
		else if (!strcmp(variables[x], "t2")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			t2 = (time_t)strtoul(variables[x], NULL, 10);
			timeperiod_type = TIMEPERIOD_CUSTOM;
			compute_time_from_parts = FALSE;
		}

		/* we found the assume initial states option */
		else if (!strcmp(variables[x], "assumeinitialstates")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (!strcmp(variables[x], "yes"))
				assume_initial_states = TRUE;
			else
				assume_initial_states = FALSE;
		}

		/* we found the assume state during program not running option */
		else if (!strcmp(variables[x], "assumestatesduringnotrunning")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (!strcmp(variables[x], "yes"))
				assume_states_during_notrunning = TRUE;
			else
				assume_states_during_notrunning = FALSE;
		}

		/* we found the initial assumed host state option */
		else if (!strcmp(variables[x], "initialassumedhoststate")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			initial_assumed_host_state = atoi(variables[x]);
		}

		/* we found the initial assumed service state option */
		else if (!strcmp(variables[x], "initialassumedservicestate")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			initial_assumed_service_state = atoi(variables[x]);
		}

		/* we found the assume state retention option */
		else if (!strcmp(variables[x], "assumestateretention")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (!strcmp(variables[x], "yes"))
				assume_state_retention = TRUE;
			else
				assume_state_retention = FALSE;
		}

		/* we found the include soft states option */
		else if (!strcmp(variables[x], "includesoftstates")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (!strcmp(variables[x], "yes"))
				include_soft_states = TRUE;
			else
				include_soft_states = FALSE;
		}

		/* we found the backtrack archives argument */
		else if (!strcmp(variables[x], "backtrack")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			backtrack_archives = atoi(variables[x]);
			if (backtrack_archives < 0)
				backtrack_archives = 0;
			if (backtrack_archives > MAX_ARCHIVE_BACKTRACKS)
				backtrack_archives = MAX_ARCHIVE_BACKTRACKS;

#ifdef DEBUG
			printf("回滚存档: %d\n", backtrack_archives);
#endif
		}

		/* we found the standard timeperiod argument */
		else if (!strcmp(variables[x], "timeperiod")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (!strcmp(variables[x], "today"))
				timeperiod_type = TIMEPERIOD_TODAY;
			else if (!strcmp(variables[x], "yesterday"))
				timeperiod_type = TIMEPERIOD_YESTERDAY;
			else if (!strcmp(variables[x], "thisweek"))
				timeperiod_type = TIMEPERIOD_THISWEEK;
			else if (!strcmp(variables[x], "lastweek"))
				timeperiod_type = TIMEPERIOD_LASTWEEK;
			else if (!strcmp(variables[x], "thismonth"))
				timeperiod_type = TIMEPERIOD_THISMONTH;
			else if (!strcmp(variables[x], "lastmonth"))
				timeperiod_type = TIMEPERIOD_LASTMONTH;
			else if (!strcmp(variables[x], "thisquarter"))
				timeperiod_type = TIMEPERIOD_THISQUARTER;
			else if (!strcmp(variables[x], "lastquarter"))
				timeperiod_type = TIMEPERIOD_LASTQUARTER;
			else if (!strcmp(variables[x], "thisyear"))
				timeperiod_type = TIMEPERIOD_THISYEAR;
			else if (!strcmp(variables[x], "lastyear"))
				timeperiod_type = TIMEPERIOD_LASTYEAR;
			else if (!strcmp(variables[x], "last24hours"))
				timeperiod_type = TIMEPERIOD_LAST24HOURS;
			else if (!strcmp(variables[x], "last7days"))
				timeperiod_type = TIMEPERIOD_LAST7DAYS;
			else if (!strcmp(variables[x], "last31days"))
				timeperiod_type = TIMEPERIOD_LAST31DAYS;
			else if (!strcmp(variables[x], "custom"))
				timeperiod_type = TIMEPERIOD_CUSTOM;
			else
				continue;

			convert_timeperiod_to_times(timeperiod_type, &t1, &t2);
			compute_time_from_parts = FALSE;
		}

		/* we found the embed option */
		else if (!strcmp(variables[x], "embedded"))
			embedded = TRUE;

		/* we found the noheader option */
		else if (!strcmp(variables[x], "noheader"))
			display_header = FALSE;

		/* we found the CSV output option */
		else if (!strcmp(variables[x], "csvoutput")) {
			display_header = FALSE;
			content_type = CSV_CONTENT;
		}

		/* we found the JSON output option */
		else if (!strcmp(variables[x], "jsonoutput")) {
			display_header = FALSE;
			content_type = JSON_CONTENT;
		}

		/* we found the XML output option */
		else if (!strcmp(variables[x], "xmloutput")) {
			display_header = FALSE;
			content_type = XML_CONTENT;
		}

		/* we found the content type argument */
		else if (!strcmp(variables[x], "content_type")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (!strcmp(variables[x], "xml"))
				content_type = XML_CONTENT;
			else if (!strcmp(variables[x], "csv"))
				content_type = CSV_CONTENT;
			else if (!strcmp(variables[x], "json"))
				content_type = JSON_CONTENT;
			else if (!strcmp(variables[x], "html"))
				content_type = HTML_CONTENT;
			else
				continue;

			if (content_type != HTML_CONTENT)
				display_header = FALSE;
		}

		/* we found the log entries option  */
		else if (!strcmp(variables[x], "show_log_entries"))
			show_log_entries = TRUE;

		/* we found the full log entries option */
		else if (!strcmp(variables[x], "full_log_entries"))
			full_log_entries = TRUE;

		/* we found the get date parts option */
		else if (!strcmp(variables[x], "get_date_parts"))
			get_date_parts = TRUE;

		/* we found the report type selection option */
		else if (!strcmp(variables[x], "report_type")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}
			if (!strcmp(variables[x], "hostgroups"))
				select_hostgroups = TRUE;
			else if (!strcmp(variables[x], "servicegroups"))
				select_servicegroups = TRUE;
			else if (!strcmp(variables[x], "hosts"))
				select_hosts = TRUE;
			else
				select_services = TRUE;
		}

		/* we found time argument */
		else if (!strcmp(variables[x], "smon")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (timeperiod_type != TIMEPERIOD_CUSTOM)
				continue;

			start_month = atoi(variables[x]);
			timeperiod_type = TIMEPERIOD_CUSTOM;
			compute_time_from_parts = TRUE;
		}

		/* we found time argument */
		else if (!strcmp(variables[x], "sday")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (timeperiod_type != TIMEPERIOD_CUSTOM)
				continue;

			start_day = atoi(variables[x]);
			timeperiod_type = TIMEPERIOD_CUSTOM;
			compute_time_from_parts = TRUE;
		}

		/* we found time argument */
		else if (!strcmp(variables[x], "syear")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (timeperiod_type != TIMEPERIOD_CUSTOM)
				continue;

			start_year = atoi(variables[x]);
			timeperiod_type = TIMEPERIOD_CUSTOM;
			compute_time_from_parts = TRUE;
		}

		/* we found time argument */
		else if (!strcmp(variables[x], "smin")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (timeperiod_type != TIMEPERIOD_CUSTOM)
				continue;

			start_minute = atoi(variables[x]);
			timeperiod_type = TIMEPERIOD_CUSTOM;
			compute_time_from_parts = TRUE;
		}

		/* we found time argument */
		else if (!strcmp(variables[x], "ssec")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (timeperiod_type != TIMEPERIOD_CUSTOM)
				continue;

			start_second = atoi(variables[x]);
			timeperiod_type = TIMEPERIOD_CUSTOM;
			compute_time_from_parts = TRUE;
		}

		/* we found time argument */
		else if (!strcmp(variables[x], "shour")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (timeperiod_type != TIMEPERIOD_CUSTOM)
				continue;

			start_hour = atoi(variables[x]);
			timeperiod_type = TIMEPERIOD_CUSTOM;
			compute_time_from_parts = TRUE;
		}


		/* we found time argument */
		else if (!strcmp(variables[x], "emon")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (timeperiod_type != TIMEPERIOD_CUSTOM)
				continue;

			end_month = atoi(variables[x]);
			timeperiod_type = TIMEPERIOD_CUSTOM;
			compute_time_from_parts = TRUE;
		}

		/* we found time argument */
		else if (!strcmp(variables[x], "eday")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (timeperiod_type != TIMEPERIOD_CUSTOM)
				continue;

			end_day = atoi(variables[x]);
			timeperiod_type = TIMEPERIOD_CUSTOM;
			compute_time_from_parts = TRUE;
		}

		/* we found time argument */
		else if (!strcmp(variables[x], "eyear")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (timeperiod_type != TIMEPERIOD_CUSTOM)
				continue;

			end_year = atoi(variables[x]);
			timeperiod_type = TIMEPERIOD_CUSTOM;
			compute_time_from_parts = TRUE;
		}

		/* we found time argument */
		else if (!strcmp(variables[x], "emin")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (timeperiod_type != TIMEPERIOD_CUSTOM)
				continue;

			end_minute = atoi(variables[x]);
			timeperiod_type = TIMEPERIOD_CUSTOM;
			compute_time_from_parts = TRUE;
		}

		/* we found time argument */
		else if (!strcmp(variables[x], "esec")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (timeperiod_type != TIMEPERIOD_CUSTOM)
				continue;

			end_second = atoi(variables[x]);
			timeperiod_type = TIMEPERIOD_CUSTOM;
			compute_time_from_parts = TRUE;
		}

		/* we found time argument */
		else if (!strcmp(variables[x], "ehour")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (timeperiod_type != TIMEPERIOD_CUSTOM)
				continue;

			end_hour = atoi(variables[x]);
			timeperiod_type = TIMEPERIOD_CUSTOM;
			compute_time_from_parts = TRUE;
		}

		/* we found the show scheduled downtime option */
		else if (!strcmp(variables[x], "showscheduleddowntime")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (!strcmp(variables[x], "yes"))
				show_scheduled_downtime = TRUE;
			else
				show_scheduled_downtime = FALSE;
		}

		/* we found the report timeperiod option */
		else if (!strcmp(variables[x], "rpttimeperiod")) {
			timeperiod *temp_timeperiod;
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			for (temp_timeperiod = timeperiod_list; temp_timeperiod != NULL; temp_timeperiod = temp_timeperiod->next) {
				if (!strcmp(url_encode(temp_timeperiod->name), variables[x])) {
					current_timeperiod = temp_timeperiod;
					break;
				}
			}
		}

		/* we found the nodaemoncheck option */
		else if (!strcmp(variables[x], "nodaemoncheck"))
			daemon_check = FALSE;

	}

	/* free memory allocated to the CGI variables */
	free_cgivars(variables);

	return error;
}



/* computes availability data for all subjects */
void compute_availability(void) {
	avail_subject *temp_subject;
	time_t current_time;

	time(&current_time);

	for (temp_subject = subject_list; temp_subject != NULL; temp_subject = temp_subject->next) {
		compute_subject_availability(temp_subject, current_time);
		compute_subject_downtime(temp_subject, current_time);
	}

	return;
}



/* computes availability data for a given subject */
void compute_subject_availability(avail_subject *subject, time_t current_time) {
	archived_state *temp_as;
	archived_state *last_as;
	time_t a;
	time_t b;
	int current_state = AS_NO_DATA;
	int have_some_real_data = FALSE;
	hoststatus *hststatus = NULL;
	servicestatus *svcstatus = NULL;
	int first_real_state = AS_NO_DATA;
	time_t initial_assumed_time;
	int initial_assumed_state = AS_NO_DATA;
	int error;


	/* if left hand of graph is after current time, we can't do anything at all.... */
	if (t1 > current_time)
		return;

	/* get current state of host or service if possible */
	if (subject->type == HOST_SUBJECT)
		hststatus = find_hoststatus(subject->host_name);
	else
		svcstatus = find_servicestatus(subject->host_name, subject->service_description);


	/************************************/
	/* INSERT CURRENT STATE (IF WE CAN) */
	/************************************/

	/* if current time DOES NOT fall within graph bounds, so we can't do anything as far as assuming current state */

	/* if we don't have any data, assume current state (if possible) */
	if (subject->as_list == NULL && current_time > t1 && current_time <= t2) {

		/* we don't have any historical information, but the current time falls within the reporting period, so use */
		/* the current status of the host/service as the starting data */
		if (subject->type == HOST_SUBJECT) {
			if (hststatus != NULL) {

				if (hststatus->status == HOST_DOWN)
					subject->last_known_state = AS_HOST_DOWN;
				else if (hststatus->status == HOST_UNREACHABLE)
					subject->last_known_state = AS_HOST_UNREACHABLE;
				else if (hststatus->status == HOST_UP)
					subject->last_known_state = AS_HOST_UP;
				else
					subject->last_known_state = AS_NO_DATA;

				if (subject->last_known_state != AS_NO_DATA) {

					/* add a dummy archived state item, so something can get graphed */
					add_archived_state(subject->last_known_state, AS_HARD_STATE, t1, "首先假定当前主机状态(虚拟日志条目)", subject);

					/* use the current state as the last known real state */
					first_real_state = subject->last_known_state;
				}
			}
		} else {
			if (svcstatus != NULL) {

				if (svcstatus->status == SERVICE_OK)
					subject->last_known_state = AS_SVC_OK;
				else if (svcstatus->status == SERVICE_WARNING)
					subject->last_known_state = AS_SVC_WARNING;
				else if (svcstatus->status == SERVICE_CRITICAL)
					subject->last_known_state = AS_SVC_CRITICAL;
				else if (svcstatus->status == SERVICE_UNKNOWN)
					subject->last_known_state = AS_SVC_UNKNOWN;
				else
					subject->last_known_state = AS_NO_DATA;

				if (subject->last_known_state != AS_NO_DATA) {

					/* add a dummy archived state item, so something can get graphed */
					add_archived_state(subject->last_known_state, AS_HARD_STATE, t1, "首先假定当前服务状态(虚拟日志条目)", subject);

					/* use the current state as the last known real state */
					first_real_state = subject->last_known_state;
				}
			}
		}
	}



	/******************************************/
	/* INSERT FIRST ASSUMED STATE (IF WE CAN) */
	/******************************************/

	if ((subject->type == HOST_SUBJECT && initial_assumed_host_state != AS_NO_DATA) || (subject->type == SERVICE_SUBJECT && initial_assumed_service_state != AS_NO_DATA)) {

		/* see if its okay to assume initial state for this subject */
		error = FALSE;
		if (subject->type == SERVICE_SUBJECT) {
			if (initial_assumed_service_state != AS_SVC_OK && initial_assumed_service_state != AS_SVC_WARNING && initial_assumed_service_state != AS_SVC_UNKNOWN && initial_assumed_service_state != AS_SVC_CRITICAL && initial_assumed_service_state != AS_CURRENT_STATE)
				error = TRUE;
			else
				initial_assumed_state = initial_assumed_service_state;
			if (initial_assumed_service_state == AS_CURRENT_STATE && svcstatus == NULL)
				error = TRUE;
		} else {
			if (initial_assumed_host_state != AS_HOST_UP && initial_assumed_host_state != AS_HOST_DOWN && initial_assumed_host_state != AS_HOST_UNREACHABLE && initial_assumed_host_state != AS_CURRENT_STATE)
				error = TRUE;
			else
				initial_assumed_state = initial_assumed_host_state;
			if (initial_assumed_host_state == AS_CURRENT_STATE && hststatus == NULL)
				error = TRUE;
		}

		/* get the current state if applicable */
		if (((subject->type == HOST_SUBJECT && initial_assumed_host_state == AS_CURRENT_STATE) || (subject->type == SERVICE_SUBJECT && initial_assumed_service_state == AS_CURRENT_STATE)) && error == FALSE) {
			if (subject->type == SERVICE_SUBJECT) {
				switch (svcstatus->status) {
				case SERVICE_OK:
					initial_assumed_state = AS_SVC_OK;
					break;
				case SERVICE_WARNING:
					initial_assumed_state = AS_SVC_WARNING;
					break;
				case SERVICE_UNKNOWN:
					initial_assumed_state = AS_SVC_UNKNOWN;
					break;
				case SERVICE_CRITICAL:
					initial_assumed_state = AS_SVC_CRITICAL;
					break;
				default:
					error = TRUE;
					break;
				}
			} else {
				switch (hststatus->status) {
				case HOST_DOWN:
					initial_assumed_state = AS_HOST_DOWN;
					break;
				case HOST_UNREACHABLE:
					initial_assumed_state = AS_HOST_UNREACHABLE;
					break;
				case HOST_UP:
					initial_assumed_state = AS_HOST_UP;
					break;
				default:
					error = TRUE;
					break;
				}
			}
		}

		if (error == FALSE) {

			/* add this assumed state entry before any entries in the list and <= t1 */
			if (subject->as_list == NULL)
				initial_assumed_time = t1;
			else if (subject->as_list->time_stamp > t1)
				initial_assumed_time = t1;
			else
				initial_assumed_time = subject->as_list->time_stamp - 1;

			if (subject->type == HOST_SUBJECT)
				add_archived_state(initial_assumed_state, AS_HARD_STATE, initial_assumed_time, "首先假定当前主机状态(虚拟日志条目)", subject);
			else
				add_archived_state(initial_assumed_state, AS_HARD_STATE, initial_assumed_time, "首先假定当前服务状态(虚拟日志条目)", subject);
		}
	}




	/**************************************/
	/* BAIL OUT IF WE DON'T HAVE ANYTHING */
	/**************************************/

	have_some_real_data = FALSE;
	for (temp_as = subject->as_list; temp_as != NULL; temp_as = temp_as->next) {
		if (temp_as->entry_type != AS_NO_DATA && temp_as->entry_type != AS_PROGRAM_START && temp_as->entry_type != AS_PROGRAM_END) {
			have_some_real_data = TRUE;
			break;
		}
	}
	if (have_some_real_data == FALSE)
		return;




	last_as = NULL;
	subject->earliest_time = t2;
	subject->latest_time = t1;


#ifdef DEBUG
	printf("--- BEGINNING/MIDDLE SECTION ---<BR>\n");
#endif

	/**********************************/
	/*    BEGINNING/MIDDLE SECTION    */
	/**********************************/

	for (temp_as = subject->as_list; temp_as != NULL; temp_as = temp_as->next) {

		/* keep this as last known state if this is the first entry or if it occurs before the starting point of the graph */
		if ((temp_as->time_stamp <= t1 || temp_as == subject->as_list) && (temp_as->entry_type != AS_NO_DATA && temp_as->entry_type != AS_PROGRAM_END && temp_as->entry_type != AS_PROGRAM_START)) {
			subject->last_known_state = temp_as->entry_type;
#ifdef DEBUG
			printf("设置最近已知状态=%d<br>\n", subject->last_known_state);
#endif
		}

		/* skip this entry if it occurs before the starting point of the graph */
		if (temp_as->time_stamp <= t1) {
#ifdef DEBUG
			printf("跳过前一事件: %d @ %lu<br>\n", temp_as->entry_type, temp_as->time_stamp);
#endif
			last_as = temp_as;
			continue;
		}

		/* graph this span if we're not on the first item */
		if (last_as != NULL) {

			a = last_as->time_stamp;
			b = temp_as->time_stamp;

			/* we've already passed the last time displayed in the graph */
			if (a > t2)
				break;

			/* only graph this data if its on the graph */
			else if (b > t1) {

				/* clip last time if it exceeds graph limits */
				if (b > t2)
					b = t2;

				/* clip first time if it precedes graph limits */
				if (a < t1)
					a = t1;

				/* save this time if its the earliest we've graphed */
				if (a < subject->earliest_time) {
					subject->earliest_time = a;
					subject->earliest_state = last_as->entry_type;
				}

				/* save this time if its the latest we've graphed */
				if (b > subject->latest_time) {
					subject->latest_time = b;
					subject->latest_state = last_as->entry_type;
				}

				/* compute availability times for this chunk */
				compute_subject_availability_times(last_as->entry_type, temp_as->entry_type, last_as->time_stamp, a, b, subject, temp_as);

				/* return if we've reached the end of the graph limits */
				if (b >= t2) {
					last_as = temp_as;
					break;
				}
			}
		}


		/* keep track of the last item */
		last_as = temp_as;
	}


#ifdef DEBUG
	printf("--- END SECTION ---<BR>\n");
#endif

	/**********************************/
	/*           END SECTION          */
	/**********************************/

	if (last_as != NULL) {

		/* don't process an entry that is beyond the limits of the graph */
		if (last_as->time_stamp < t2) {

			time(&current_time);
			b = current_time;
			if (b > t2)
				b = t2;

			a = last_as->time_stamp;
			if (a < t1)
				a = t1;

			/* fake the current state (it doesn't really matter for graphing) */
			if (subject->type == HOST_SUBJECT)
				current_state = AS_HOST_UP;
			else
				current_state = AS_SVC_OK;

			/* compute availability times for last state */
			compute_subject_availability_times(last_as->entry_type, current_state, last_as->time_stamp, a, b, subject, last_as);
		}
	}


	return;
}


/* computes availability times */
void compute_subject_availability_times(int first_state, int last_state, time_t real_start_time, time_t start_time, time_t end_time, avail_subject *subject, archived_state *as) {
	int start_state;
	int end_state;
	unsigned long state_duration;
	struct tm *t;
	unsigned long midnight_today;
	int weekday;
	timerange *temp_timerange;
	unsigned long temp_duration;
	unsigned long temp_end;
	unsigned long temp_start;
	unsigned long start;
	unsigned long end;

#ifdef DEBUG
	if (subject->type == HOST_SUBJECT)
		printf("主机'%s'...\n", subject->host_name);
	else
		printf("主机'%s'上'%s'服务'...\n", subject->host_name, subject->service_description);

	printf("计算 %d->%d %s从%lu到%lu(%lu秒)<br>\n", first_state, last_state, (subject->type==HOST_SUBJECT)?"主机" : "服务", start_time, end_time,(end_time-start_time));
#endif

	/* clip times if necessary */
	if (start_time < t1)
		start_time = t1;
	if (end_time > t2)
		end_time = t2;

	/* make sure this is a valid time */
	if (start_time > t2)
		return;
	if (end_time < t1)
		return;

	/* MickeM - attempt to handle the current time_period (if any) */
	if (current_timeperiod != NULL) {
		t = localtime((time_t *)&start_time);
		state_duration = 0;

		/* calculate the start of the day (midnight, 00:00 hours) */
		t->tm_sec = 0;
		t->tm_min = 0;
		t->tm_hour = 0;
		t->tm_isdst = -1;
		midnight_today = (unsigned long)mktime(t);
		weekday = t->tm_wday;

		while (midnight_today < end_time) {
			temp_duration = 0;
			temp_end = min(86400, end_time - midnight_today);
			temp_start = 0;
			if (start_time > midnight_today)
				temp_start = start_time - midnight_today;
#ifdef DEBUG
			printf("<b>匹配: %ld -> %ld. (%ld -> %ld)</b><br>\n", temp_start, temp_end, midnight_today + temp_start, midnight_today + temp_end);
#endif
			/* check all time ranges for this day of the week */
			for (temp_timerange = current_timeperiod->days[weekday]; temp_timerange != NULL; temp_timerange = temp_timerange->next) {

#ifdef DEBUG
				printf("<li>匹配时间范围[%d]: %d -> %d (%ld -> %ld)<br>\n", weekday, temp_timerange->range_start, temp_timerange->range_end, temp_start, temp_end);
#endif
				start = max(temp_timerange->range_start, temp_start);
				end = min(temp_timerange->range_end, temp_end);

				if (start < end) {
					temp_duration += end - start;
#ifdef DEBUG
					printf("<li>匹配时间: %ld -> %ld = %d<br>\n", start, end, temp_duration);
#endif
				}
#ifdef DEBUG
				else
					printf("<li>忽略时间: %ld -> %ld<br>\n", start, end);
#endif
			}
			state_duration += temp_duration;
			temp_start = 0;
			midnight_today += 86400;
			if (++weekday > 6)
				weekday = 0;
		}
	}

	/* no report timeperiod was selected (assume 24x7) */
	else {
		/* calculate time in this state */
		state_duration = (unsigned long)(end_time - start_time);
	}

	/* can't graph if we don't have data... */
	if (first_state == AS_NO_DATA || last_state == AS_NO_DATA) {
		subject->time_indeterminate_nodata += state_duration;
		return;
	}
	if (first_state == AS_PROGRAM_START && (last_state == AS_PROGRAM_END || last_state == AS_PROGRAM_START)) {
		if (assume_initial_states == FALSE) {
			subject->time_indeterminate_nodata += state_duration;
			return;
		}
	}
	if (first_state == AS_PROGRAM_END) {

		/* added 7/24/03 */
		if (assume_states_during_notrunning == TRUE) {
			first_state = subject->last_known_state;
		} else {
			subject->time_indeterminate_notrunning += state_duration;
			return;
		}
	}

	/* special case if first entry was program start */
	if (first_state == AS_PROGRAM_START) {

		if (assume_initial_states == TRUE) {

			if (assume_state_retention == TRUE)
				start_state = subject->last_known_state;

			else {
				if (subject->type == HOST_SUBJECT)
					start_state = AS_HOST_UP;
				else
					start_state = AS_SVC_OK;
			}
		} else
			return;
	} else {
		start_state = first_state;
		subject->last_known_state = first_state;
	}

	/* special case if last entry was program stop */
	if (last_state == AS_PROGRAM_END)
		end_state = first_state;
	else
		end_state = last_state;

	/* save "processed state" info */
	as->processed_state = start_state;

#ifdef DEBUG
	printf("通过时间检查,取值: 开始=%lu, 结束=%lu\n", start_time, end_time);
#endif


	/* add time in this state to running totals */
	switch (start_state) {
	case AS_HOST_UP:
		subject->time_up += state_duration;
		break;
	case AS_HOST_DOWN:
		subject->time_down += state_duration;
		break;
	case AS_HOST_UNREACHABLE:
		subject->time_unreachable += state_duration;
		break;
	case AS_SVC_OK:
		subject->time_ok += state_duration;
		break;
	case AS_SVC_WARNING:
		subject->time_warning += state_duration;
		break;
	case AS_SVC_UNKNOWN:
		subject->time_unknown += state_duration;
		break;
	case AS_SVC_CRITICAL:
		subject->time_critical += state_duration;
		break;
	default:
		break;
	}

	return;
}


/* computes downtime data for a given subject */
void compute_subject_downtime(avail_subject *subject, time_t current_time) {
	archived_state *temp_sd;
	time_t start_time;
	time_t end_time;
	int host_downtime_depth = 0;
	int service_downtime_depth = 0;
	int process_chunk = FALSE;

#ifdef DEBUG2
	printf("计算机宕机主题\n");
#endif

	/* if left hand of graph is after current time, we can't do anything at all.... */
	if (t1 > current_time)
		return;

	/* no scheduled downtime data for subject... */
	if (subject->sd_list == NULL)
		return;

	/* all data we have occurs after last time on graph... */
	if (subject->sd_list->time_stamp >= t2)
		return;

	/* initialize pointer */
	temp_sd = subject->sd_list;

	/* special case if first entry is the end of scheduled downtime */
	if ((temp_sd->entry_type == AS_HOST_DOWNTIME_END || temp_sd->entry_type == AS_SVC_DOWNTIME_END) && temp_sd->time_stamp > t1) {

#ifdef DEBUG2
		printf("\t特定宕机情况\n");
#endif
		start_time = t1;
		end_time = (temp_sd->time_stamp > t2) ? t2 : temp_sd->time_stamp;
		compute_subject_downtime_times(start_time, end_time, subject, NULL);
		temp_sd = temp_sd->next;
	}

	/* process all periods of scheduled downtime */
	for (; temp_sd != NULL; temp_sd = temp_sd->next) {

		/* we've passed graph bounds... */
		if (temp_sd->time_stamp >= t2)
			break;

		if (temp_sd->entry_type == AS_HOST_DOWNTIME_START)
			host_downtime_depth++;
		else if (temp_sd->entry_type == AS_HOST_DOWNTIME_END)
			host_downtime_depth--;
		else if (temp_sd->entry_type == AS_SVC_DOWNTIME_START)
			service_downtime_depth++;
		else if (temp_sd->entry_type == AS_SVC_DOWNTIME_END)
			service_downtime_depth--;
		else
			continue;

		process_chunk = FALSE;
		if (temp_sd->entry_type == AS_HOST_DOWNTIME_START || temp_sd->entry_type == AS_SVC_DOWNTIME_START)
			process_chunk = TRUE;
		else if (subject->type == SERVICE_SUBJECT && (host_downtime_depth > 0 || service_downtime_depth > 0))
			process_chunk = TRUE;

		/* process this specific "chunk" of scheduled downtime */
		if (process_chunk == TRUE) {

			start_time = temp_sd->time_stamp;
			end_time = (temp_sd->next == NULL) ? current_time : temp_sd->next->time_stamp;

			/* check time sanity */
			if (end_time <= t1)
				continue;
			if (start_time >= t2)
				continue;
			if (start_time >= end_time)
				continue;

			/* clip time values */
			if (start_time < t1)
				start_time = t1;
			if (end_time > t2)
				end_time = t2;

			compute_subject_downtime_times(start_time, end_time, subject, temp_sd);
		}
	}

	return;
}



/* computes downtime times */
void compute_subject_downtime_times(time_t start_time, time_t end_time, avail_subject *subject, archived_state *sd) {
	archived_state *temp_as = NULL;
	time_t part_start_time = 0L;
	time_t part_subject_state = 0L;
	int saved_status = 0;
	int saved_stamp = 0;
	int count = 0;
	archived_state *temp_before = NULL;
	archived_state *last = NULL;

#ifdef DEBUG2
	printf("<P><b>输入计算机宕机主题时间: 开始=%lu, 结束=%lu, t1=%lu, t2=%lu </b></P>", start_time, end_time, t1, t2);
#endif

	/* times are weird, so bail out... */
	if (start_time > end_time)
		return;
	if (start_time < t1 || end_time > t2)
		return;

	/* find starting point in archived state list */
	if (sd == NULL) {
#ifdef DEBUG2
		printf("<P>TEMP_AS=SUBJECT->AS_LIST </P>");
#endif
		temp_as = subject->as_list;
	} else if (sd->misc_ptr == NULL) {
#ifdef DEBUG2
		printf("<P>TEMP_AS=SUBJECT->AS_LIST</P>");
#endif
		temp_as = subject->as_list;
	} else if (sd->misc_ptr->next == NULL) {
#ifdef DEBUG2
		printf("<P>TEMP_AS=SD->MISC_PTR</P>");
#endif
		temp_as = sd->misc_ptr;
	} else {
#ifdef DEBUG2
		printf("<P>TEMP_AS=SD->MISC_PTR->NEXT</P>");
#endif
		temp_as = sd->misc_ptr->next;
	}

	/* initialize values */
	part_start_time = start_time;
	if (temp_as == NULL)
		part_subject_state = AS_NO_DATA;
	else if (temp_as->processed_state == AS_PROGRAM_START || temp_as->processed_state == AS_PROGRAM_END || temp_as->processed_state == AS_NO_DATA) {
#ifdef DEBUG2
		printf("<P>输入类型 #1: %d</P>", temp_as->entry_type);
#endif
		part_subject_state = AS_NO_DATA;
	} else {
#ifdef DEBUG2
		printf("<P>输入类型 #2: %d</P>", temp_as->entry_type);
#endif
		part_subject_state = temp_as->processed_state;
	}

#ifdef DEBUG2
	printf("<P>TEMP_AS=%s</P>", (temp_as == NULL) ? "空" : "非空");
	printf("<P>SD=%s</P>", (sd == NULL) ? "空" : "非空");
#endif

	/* temp_as now points to first event to possibly "break" this chunk */
	for (; temp_as != NULL; temp_as = temp_as->next) {
		count++;
		last = temp_as;

		if (temp_before == NULL) {
			if (last->time_stamp > start_time) {
				if (last->time_stamp > end_time)
					compute_subject_downtime_part_times(start_time, end_time, part_subject_state, subject);
				else
					compute_subject_downtime_part_times(start_time, last->time_stamp, part_subject_state, subject);
			}
			temp_before = temp_as;
			saved_status = temp_as->entry_type;
			saved_stamp = temp_as->time_stamp;

			/* check if first time is before schedule downtime */
			if (saved_stamp < start_time)
				saved_stamp = start_time;

			continue;
		}

		/* if status changed, we have to calculate */
		if (saved_status != temp_as->entry_type) {

			/* is outside schedule time, use end schdule downtime */
			if (temp_as->time_stamp > end_time) {
				if (saved_stamp < start_time)
					compute_subject_downtime_part_times(start_time, end_time, saved_status, subject);
				else
					compute_subject_downtime_part_times(saved_stamp, end_time, saved_status, subject);
			} else {
				if (saved_stamp < start_time)
					compute_subject_downtime_part_times(start_time, temp_as->time_stamp, saved_status, subject);
				else
					compute_subject_downtime_part_times(saved_stamp, temp_as->time_stamp, saved_status, subject);
			}
			saved_status = temp_as->entry_type;
			saved_stamp = temp_as->time_stamp;
		}
	}

	/* just one entry inside the scheduled downtime */
	if (count == 0)
		compute_subject_downtime_part_times(start_time, end_time, part_subject_state, subject);
	else {
		/* is outside scheduled time, use end schdule downtime */
		if (last->time_stamp > end_time)
			compute_subject_downtime_part_times(saved_stamp, end_time, saved_status, subject);
		else
			compute_subject_downtime_part_times(saved_stamp, last->time_stamp, saved_status, subject);
	}

	return;
}



/* computes downtime times */
void compute_subject_downtime_part_times(time_t start_time, time_t end_time, int subject_state, avail_subject *subject) {
	unsigned long state_duration;

#ifdef DEBUG2
	printf("输入计算机宕机主题部分时间\n");
#endif

	/* times are weird */
	if (start_time > end_time)
		return;

	state_duration = (unsigned long)(end_time - start_time);

	switch (subject_state) {
	case AS_HOST_UP:
		subject->scheduled_time_up += state_duration;
		break;
	case AS_HOST_DOWN:
		subject->scheduled_time_down += state_duration;
		break;
	case AS_HOST_UNREACHABLE:
		subject->scheduled_time_unreachable += state_duration;
		break;
	case AS_SVC_OK:
		subject->scheduled_time_ok += state_duration;
		break;
	case AS_SVC_WARNING:
		subject->scheduled_time_warning += state_duration;
		break;
	case AS_SVC_UNKNOWN:
		subject->scheduled_time_unknown += state_duration;
		break;
	case AS_SVC_CRITICAL:
		subject->scheduled_time_critical += state_duration;
		break;
	default:
		subject->scheduled_time_indeterminate += state_duration;
		break;
	}

#ifdef DEBUG2
	printf("\t宕机主题: 主机 %s', 服务'%s', 状态=%d, 持续时间=%lu, 开始=%lu\n", subject->host_name, (subject->service_description == NULL) ? "NULL" : subject->service_description, subject_state, state_duration, start_time);
#endif

	return;
}



/* convert current host state to archived state value */
int convert_host_state_to_archived_state(int current_status) {

	if (current_status == HOST_UP)
		return AS_HOST_UP;
	if (current_status == HOST_DOWN)
		return AS_HOST_DOWN;
	if (current_status == HOST_UNREACHABLE)
		return AS_HOST_UNREACHABLE;

	return AS_NO_DATA;
}


/* convert current service state to archived state value */
int convert_service_state_to_archived_state(int current_status) {

	if (current_status == SERVICE_OK)
		return AS_SVC_OK;
	if (current_status == SERVICE_UNKNOWN)
		return AS_SVC_UNKNOWN;
	if (current_status == SERVICE_WARNING)
		return AS_SVC_WARNING;
	if (current_status == SERVICE_CRITICAL)
		return AS_SVC_CRITICAL;

	return AS_NO_DATA;
}



/* create list of subjects to collect availability data for */
void create_subject_list(void) {
	hostgroup *temp_hostgroup;
	hostsmember *temp_hgmember;
	servicegroup *temp_servicegroup;
	servicesmember *temp_sgmember;
	host *temp_host;
	service *temp_service;
	char *last_host_name = "";

	/* we're displaying one or more hosts */
	if (display_type == DISPLAY_HOST_AVAIL && host_name && strcmp(host_name, "")) {

		/* we're only displaying a specific host (and summaries for all services associated with it) */
		if (show_all_hosts == FALSE) {
			add_subject(HOST_SUBJECT, host_name, NULL);
			for (temp_service = service_list; temp_service != NULL; temp_service = temp_service->next) {
				if (!strcmp(temp_service->host_name, host_name))
					add_subject(SERVICE_SUBJECT, host_name, temp_service->description);
			}
		}

		/* we're displaying all hosts */
		else {
			for (temp_host = host_list; temp_host != NULL; temp_host = temp_host->next)
				add_subject(HOST_SUBJECT, temp_host->name, NULL);
		}
	}

	/* we're displaying a specific service */
	else if (display_type == DISPLAY_SERVICE_AVAIL && service_desc && strcmp(service_desc, "")) {

		/* we're only displaying a specific service */
		if (show_all_services == FALSE)
			add_subject(SERVICE_SUBJECT, host_name, service_desc);

		/* we're displaying all services */
		else {
			for (temp_service = service_list; temp_service != NULL; temp_service = temp_service->next)
				add_subject(SERVICE_SUBJECT, temp_service->host_name, temp_service->description);
		}
	}

	/* we're displaying one or more hostgroups (the host members of the groups) */
	else if (display_type == DISPLAY_HOSTGROUP_AVAIL && hostgroup_name && strcmp(hostgroup_name, "")) {

		/* we're displaying all hostgroups */
		if (show_all_hostgroups == TRUE) {
			for (temp_hostgroup = hostgroup_list; temp_hostgroup != NULL; temp_hostgroup = temp_hostgroup->next) {
				for (temp_hgmember = temp_hostgroup->members; temp_hgmember != NULL; temp_hgmember = temp_hgmember->next)
					add_subject(HOST_SUBJECT, temp_hgmember->host_name, NULL);
			}
		}
		/* we're only displaying a specific hostgroup */
		else {
			temp_hostgroup = find_hostgroup(hostgroup_name);
			if (temp_hostgroup != NULL) {
				for (temp_hgmember = temp_hostgroup->members; temp_hgmember != NULL; temp_hgmember = temp_hgmember->next)
					add_subject(HOST_SUBJECT, temp_hgmember->host_name, NULL);
			}
		}
	}

	/* we're displaying one or more servicegroups (the host and service members of the groups) */
	else if (display_type == DISPLAY_SERVICEGROUP_AVAIL && servicegroup_name && strcmp(servicegroup_name, "")) {

		/* we're displaying all servicegroups */
		if (show_all_servicegroups == TRUE) {
			for (temp_servicegroup = servicegroup_list; temp_servicegroup != NULL; temp_servicegroup = temp_servicegroup->next) {
				for (temp_sgmember = temp_servicegroup->members; temp_sgmember != NULL; temp_sgmember = temp_sgmember->next) {
					add_subject(SERVICE_SUBJECT, temp_sgmember->host_name, temp_sgmember->service_description);
					if (strcmp(last_host_name, temp_sgmember->host_name))
						add_subject(HOST_SUBJECT, temp_sgmember->host_name, NULL);
					last_host_name = temp_sgmember->host_name;
				}
			}
		}
		/* we're only displaying a specific servicegroup */
		else {
			temp_servicegroup = find_servicegroup(servicegroup_name);
			if (temp_servicegroup != NULL) {
				for (temp_sgmember = temp_servicegroup->members; temp_sgmember != NULL; temp_sgmember = temp_sgmember->next) {
					add_subject(SERVICE_SUBJECT, temp_sgmember->host_name, temp_sgmember->service_description);
					if (strcmp(last_host_name, temp_sgmember->host_name))
						add_subject(HOST_SUBJECT, temp_sgmember->host_name, NULL);
					last_host_name = temp_sgmember->host_name;
				}
			}
		}
	}

	return;
}



/* adds a subject */
void add_subject(int subject_type, char *hn, char *sd) {
	avail_subject *last_subject = NULL;
	avail_subject *temp_subject = NULL;
	avail_subject *new_subject = NULL;
	int is_authorized = FALSE;

	/* bail if we've already added the subject */
	if (find_subject(subject_type, hn, sd))
		return;

	/* see if the user is authorized to see data for this host or service */
	if (subject_type == HOST_SUBJECT)
		is_authorized = is_authorized_for_host(find_host(hn), &current_authdata);
	else
		is_authorized = is_authorized_for_service(find_service(hn, sd), &current_authdata);
	if (is_authorized == FALSE)
		return;

	/* allocate memory for the new entry */
	new_subject = (avail_subject *)malloc(sizeof(avail_subject));
	if (new_subject == NULL)
		return;

	/* allocate memory for the host name */
	if (hn != NULL) {
		new_subject->host_name = (char *)malloc(strlen(hn) + 1);
		if (new_subject->host_name != NULL)
			strcpy(new_subject->host_name, hn);
	} else
		new_subject->host_name = NULL;

	/* allocate memory for the service description */
	if (sd != NULL) {
		new_subject->service_description = (char *)malloc(strlen(sd) + 1);
		if (new_subject->service_description != NULL)
			strcpy(new_subject->service_description, sd);
	} else
		new_subject->service_description = NULL;

	new_subject->type = subject_type;
	new_subject->earliest_state = AS_NO_DATA;
	new_subject->latest_state = AS_NO_DATA;
	new_subject->time_up = 0L;
	new_subject->time_down = 0L;
	new_subject->time_unreachable = 0L;
	new_subject->time_ok = 0L;
	new_subject->time_warning = 0L;
	new_subject->time_unknown = 0L;
	new_subject->time_critical = 0L;
	new_subject->scheduled_time_up = 0L;
	new_subject->scheduled_time_down = 0L;
	new_subject->scheduled_time_unreachable = 0L;
	new_subject->scheduled_time_ok = 0L;
	new_subject->scheduled_time_warning = 0L;
	new_subject->scheduled_time_unknown = 0L;
	new_subject->scheduled_time_critical = 0L;
	new_subject->scheduled_time_indeterminate = 0L;
	new_subject->time_indeterminate_nodata = 0L;
	new_subject->time_indeterminate_notrunning = 0L;
	new_subject->as_list = NULL;
	new_subject->as_list_tail = NULL;
	new_subject->sd_list = NULL;
	new_subject->last_known_state = AS_NO_DATA;

	/* add the new entry to the list in memory, sorted by host name */
	last_subject = subject_list;
	for (temp_subject = subject_list; temp_subject != NULL; temp_subject = temp_subject->next) {
		if (strcmp(new_subject->host_name, temp_subject->host_name) < 0) {
			new_subject->next = temp_subject;
			if (temp_subject == subject_list)
				subject_list = new_subject;
			else
				last_subject->next = new_subject;
			break;
		} else
			last_subject = temp_subject;
	}
	if (subject_list == NULL) {
		new_subject->next = NULL;
		subject_list = new_subject;
	} else if (temp_subject == NULL) {
		new_subject->next = NULL;
		last_subject->next = new_subject;
	}

	return;
}



/* finds a specific subject */
avail_subject *find_subject(int type, char *hn, char *sd) {
	avail_subject *temp_subject;

	if (hn == NULL)
		return NULL;

	if (type == SERVICE_SUBJECT && sd == NULL)
		return NULL;

	for (temp_subject = subject_list; temp_subject != NULL; temp_subject = temp_subject->next) {
		if (temp_subject->type != type)
			continue;
		if (strcmp(hn, temp_subject->host_name))
			continue;
		if (type == SERVICE_SUBJECT && strcmp(sd, temp_subject->service_description))
			continue;
		return temp_subject;
	}

	return NULL;
}



/* adds an archived state entry to all subjects */
void add_global_archived_state(int entry_type, int state_type, time_t time_stamp, char *state_info) {
	avail_subject *temp_subject;

	for (temp_subject = subject_list; temp_subject != NULL; temp_subject = temp_subject->next)
		add_archived_state(entry_type, state_type, time_stamp, state_info, temp_subject);

	return;
}




/* adds an archived state entry to a specific subject */
void add_archived_state(int entry_type, int state_type, time_t time_stamp, char *state_info, avail_subject *subject) {
	archived_state *last_as = NULL;
	archived_state *temp_as = NULL;
	archived_state *new_as = NULL;

	/* allocate memory for the new entry */
	new_as = (archived_state *)malloc(sizeof(archived_state));
	if (new_as == NULL)
		return;

	/* allocate memory for the state info */
	if (state_info != NULL) {
		new_as->state_info = (char *)malloc(strlen(state_info) + 1);
		if (new_as->state_info != NULL)
			strcpy(new_as->state_info, state_info);
	} else new_as->state_info = NULL;

	/* initialize the "processed state" value - this gets modified later for most entries */
	if (entry_type != AS_PROGRAM_START && entry_type != AS_PROGRAM_END && entry_type != AS_NO_DATA)
		new_as->processed_state = entry_type;
	else
		new_as->processed_state = AS_NO_DATA;

	new_as->entry_type = entry_type;
	new_as->state_type = state_type;
	new_as->time_stamp = time_stamp;
	new_as->misc_ptr = NULL;

	/* add the new entry to the list in memory, sorted by time (more recent entries should appear towards end of list) */
	last_as = subject->as_list;
	for (temp_as = subject->as_list; temp_as != NULL; temp_as = temp_as->next) {
		if (new_as->time_stamp < temp_as->time_stamp) {
			new_as->next = temp_as;
			if (temp_as == subject->as_list)
				subject->as_list = new_as;
			else
				last_as->next = new_as;
			break;
		} else
			last_as = temp_as;
	}
	if (subject->as_list == NULL) {
		new_as->next = NULL;
		subject->as_list = new_as;
	} else if (temp_as == NULL) {
		new_as->next = NULL;
		last_as->next = new_as;
	}

	/* update "tail" of the list - not really the tail, just last item added */
	subject->as_list_tail = new_as;

	return;
}


/* adds a scheduled downtime entry to a specific subject */
void add_scheduled_downtime(int state_type, time_t time_stamp, avail_subject *subject) {
	archived_state *last_sd = NULL;
	archived_state *temp_sd = NULL;
	archived_state *new_sd = NULL;

	/* allocate memory for the new entry */
	new_sd = (archived_state *)malloc(sizeof(archived_state));
	if (new_sd == NULL)
		return;

	new_sd->state_info = NULL;
	new_sd->processed_state = state_type;
	new_sd->entry_type = state_type;
	new_sd->time_stamp = time_stamp;
	new_sd->misc_ptr = subject->as_list_tail;

	/* add the new entry to the list in memory, sorted by time (more recent entries should appear towards end of list) */
	last_sd = subject->sd_list;
	for (temp_sd = subject->sd_list; temp_sd != NULL; temp_sd = temp_sd->next) {
		if (new_sd->time_stamp <= temp_sd->time_stamp) {
			new_sd->next = temp_sd;
			if (temp_sd == subject->sd_list)
				subject->sd_list = new_sd;
			else
				last_sd->next = new_sd;
			break;
		} else
			last_sd = temp_sd;
	}
	if (subject->sd_list == NULL) {
		new_sd->next = NULL;
		subject->sd_list = new_sd;
	} else if (temp_sd == NULL) {
		new_sd->next = NULL;
		last_sd->next = new_sd;
	}

	return;
}


/* frees memory allocated to all availability data */
void free_availability_data(void) {
	avail_subject *this_subject;
	avail_subject *next_subject;

	for (this_subject = subject_list; this_subject != NULL;) {
		next_subject = this_subject->next;
		if (this_subject->host_name != NULL)
			free(this_subject->host_name);
		if (this_subject->service_description != NULL)
			free(this_subject->service_description);
		free_archived_state_list(this_subject->as_list);
		free_archived_state_list(this_subject->sd_list);
		free(this_subject);
		this_subject = next_subject;
	}

	return;
}

/* frees memory allocated to the archived state list */
void free_archived_state_list(archived_state *as_list) {
	archived_state *this_as = NULL;
	archived_state *next_as = NULL;

	for (this_as = as_list; this_as != NULL;) {
		next_as = this_as->next;
		if (this_as->state_info != NULL)
			free(this_as->state_info);
		free(this_as);
		this_as = next_as;
	}

	as_list = NULL;

	return;
}



/* reads log files for archived state data */
void read_archived_state_data(void) {
	char entry_host_name[MAX_INPUT_BUFFER];
	char entry_service_desc[MAX_INPUT_BUFFER];
	char *plugin_output = NULL;
	char *temp_buffer = NULL;
	char *error_text = NULL;
	avail_subject *temp_subject = NULL;
	logentry *temp_entry = NULL;
	int state_type = 0;
	int status = READLOG_OK;
	logentry *entry_list = NULL;
	logfilter *filter_list = NULL;

	status = get_log_entries(&entry_list, &filter_list, &error_text, NULL, FALSE, t1 - get_backtrack_seconds(backtrack_archives), t2);

	if (status != READLOG_ERROR_FATAL) {

		for (temp_entry = entry_list; temp_entry != NULL; temp_entry = temp_entry->next) {

			/* program starts/restarts */
			if (temp_entry->type == LOGENTRY_STARTUP)
				add_global_archived_state(AS_PROGRAM_START, AS_NO_DATA, temp_entry->timestamp, "启动程序");
			if (temp_entry->type == LOGENTRY_RESTART)
				add_global_archived_state(AS_PROGRAM_START, AS_NO_DATA, temp_entry->timestamp, "重启程序");

			/* program stops */
			if (temp_entry->type == LOGENTRY_SHUTDOWN)
				add_global_archived_state(AS_PROGRAM_END, AS_NO_DATA, temp_entry->timestamp, "正常终止程序");
			if (temp_entry->type == LOGENTRY_BAILOUT)
				add_global_archived_state(AS_PROGRAM_END, AS_NO_DATA, temp_entry->timestamp, "异常终止程序");

			if (display_type == DISPLAY_HOST_AVAIL || display_type == DISPLAY_HOSTGROUP_AVAIL || display_type == DISPLAY_SERVICEGROUP_AVAIL) {

				switch (temp_entry->type) {

					/* normal host alerts and initial/current states */
				case LOGENTRY_HOST_DOWN:
				case LOGENTRY_HOST_UNREACHABLE:
				case LOGENTRY_HOST_RECOVERY:
				case LOGENTRY_HOST_UP:
				case LOGENTRY_HOST_INITIAL_STATE:
				case LOGENTRY_HOST_CURRENT_STATE:

					/* get host name */
					temp_buffer = my_strtok(temp_entry->entry_text, ":");
					temp_buffer = my_strtok(NULL, ";");
					strncpy(entry_host_name, (temp_buffer == NULL) ? "" : temp_buffer + 1, sizeof(entry_host_name));
					entry_host_name[sizeof(entry_host_name)-1] = '\x0';

					/* see if there is a corresponding subject for this host */
					temp_subject = find_subject(HOST_SUBJECT, entry_host_name, NULL);
					if (temp_subject == NULL)
						break;

					/* state types */
					if (strstr(temp_entry->entry_text, ";软件状态;")) {
						if (include_soft_states == FALSE)
							break;
						state_type = AS_SOFT_STATE;
					}
					if (strstr(temp_entry->entry_text, ";硬件状态;"))
						state_type = AS_HARD_STATE;

					/* get the plugin output */
					temp_buffer = my_strtok(NULL, ";");
					temp_buffer = my_strtok(NULL, ";");
					temp_buffer = my_strtok(NULL, ";");
					plugin_output = my_strtok(NULL, "\n");

					if (strstr(temp_entry->entry_text, ";宕机;"))
						add_archived_state(AS_HOST_DOWN, state_type, temp_entry->timestamp, plugin_output, temp_subject);
					else if (strstr(temp_entry->entry_text, ";不可达;"))
						add_archived_state(AS_HOST_UNREACHABLE, state_type, temp_entry->timestamp, plugin_output, temp_subject);
					else if (strstr(temp_entry->entry_text, ";恢复;") || strstr(temp_entry->entry_text, ";运行;"))
						add_archived_state(AS_HOST_UP, state_type, temp_entry->timestamp, plugin_output, temp_subject);
					else
						add_archived_state(AS_NO_DATA, AS_NO_DATA, temp_entry->timestamp, plugin_output, temp_subject);

					break;

					/* scheduled downtime notices */
				case LOGENTRY_HOST_DOWNTIME_STARTED:
				case LOGENTRY_HOST_DOWNTIME_STOPPED:
				case LOGENTRY_HOST_DOWNTIME_CANCELLED:

					/* get host name */
					temp_buffer = my_strtok(temp_entry->entry_text, ":");
					temp_buffer = my_strtok(NULL, ";");
					strncpy(entry_host_name, (temp_buffer == NULL) ? "" : temp_buffer + 1, sizeof(entry_host_name));
					entry_host_name[sizeof(entry_host_name)-1] = '\x0';

					/* see if there is a corresponding subject for this host */
					temp_subject = find_subject(HOST_SUBJECT, entry_host_name, NULL);
					if (temp_subject == NULL)
						break;

					if (show_scheduled_downtime == FALSE)
						break;

					if (temp_entry->type == LOGENTRY_HOST_DOWNTIME_STARTED)
						add_scheduled_downtime(AS_HOST_DOWNTIME_START, temp_entry->timestamp, temp_subject);
					else
						add_scheduled_downtime(AS_HOST_DOWNTIME_END, temp_entry->timestamp, temp_subject);

					break;
				}
			}

			if (display_type == DISPLAY_SERVICE_AVAIL || display_type == DISPLAY_HOST_AVAIL || display_type == DISPLAY_SERVICEGROUP_AVAIL) {

				switch (temp_entry->type) {

					/* normal service alerts and initial/current states */
				case LOGENTRY_SERVICE_CRITICAL:
				case LOGENTRY_SERVICE_WARNING:
				case LOGENTRY_SERVICE_UNKNOWN:
				case LOGENTRY_SERVICE_RECOVERY:
				case LOGENTRY_SERVICE_OK:
				case LOGENTRY_SERVICE_INITIAL_STATE:
				case LOGENTRY_SERVICE_CURRENT_STATE:

					/* get host name */
					temp_buffer = my_strtok(temp_entry->entry_text, ":");
					temp_buffer = my_strtok(NULL, ";");
					strncpy(entry_host_name, (temp_buffer == NULL) ? "" : temp_buffer + 1, sizeof(entry_host_name));
					entry_host_name[sizeof(entry_host_name)-1] = '\x0';

					/* get service description */
					temp_buffer = my_strtok(NULL, ";");
					strncpy(entry_service_desc, (temp_buffer == NULL) ? "" : temp_buffer, sizeof(entry_service_desc));
					entry_service_desc[sizeof(entry_service_desc)-1] = '\x0';

					/* see if there is a corresponding subject for this service */
					temp_subject = find_subject(SERVICE_SUBJECT, entry_host_name, entry_service_desc);
					if (temp_subject == NULL)
						break;

					/* state types */
					if (strstr(temp_entry->entry_text, ";软件状态;")) {
						if (include_soft_states == FALSE)
							break;
						state_type = AS_SOFT_STATE;
					}
					if (strstr(temp_entry->entry_text, ";硬件状态;"))
						state_type = AS_HARD_STATE;

					/* get the plugin output */
					temp_buffer = my_strtok(NULL, ";");
					temp_buffer = my_strtok(NULL, ";");
					temp_buffer = my_strtok(NULL, ";");
					plugin_output = my_strtok(NULL, "\n");

					if (strstr(temp_entry->entry_text, ";严重;"))
						add_archived_state(AS_SVC_CRITICAL, state_type, temp_entry->timestamp, plugin_output, temp_subject);
					else if (strstr(temp_entry->entry_text, ";警报;"))
						add_archived_state(AS_SVC_WARNING, state_type, temp_entry->timestamp, plugin_output, temp_subject);
					else if (strstr(temp_entry->entry_text, ";未知;"))
						add_archived_state(AS_SVC_UNKNOWN, state_type, temp_entry->timestamp, plugin_output, temp_subject);
					else if (strstr(temp_entry->entry_text, ";恢复;") || strstr(temp_entry->entry_text, ";正常;"))
						add_archived_state(AS_SVC_OK, state_type, temp_entry->timestamp, plugin_output, temp_subject);
					else
						add_archived_state(AS_NO_DATA, AS_NO_DATA, temp_entry->timestamp, plugin_output, temp_subject);

					break;

					/* scheduled service downtime notices */
				case LOGENTRY_SERVICE_DOWNTIME_STARTED:
				case LOGENTRY_SERVICE_DOWNTIME_STOPPED:
				case LOGENTRY_SERVICE_DOWNTIME_CANCELLED:

					/* get host name */
					temp_buffer = my_strtok(temp_entry->entry_text, ":");
					temp_buffer = my_strtok(NULL, ";");
					strncpy(entry_host_name, (temp_buffer == NULL) ? "" : temp_buffer + 1, sizeof(entry_host_name));
					entry_host_name[sizeof(entry_host_name)-1] = '\x0';

					/* get service description */
					temp_buffer = my_strtok(NULL, ";");
					strncpy(entry_service_desc, (temp_buffer == NULL) ? "" : temp_buffer, sizeof(entry_service_desc));
					entry_service_desc[sizeof(entry_service_desc)-1] = '\x0';

					/* see if there is a corresponding subject for this service */
					temp_subject = find_subject(SERVICE_SUBJECT, entry_host_name, entry_service_desc);
					if (temp_subject == NULL)
						break;

					if (show_scheduled_downtime == FALSE)
						break;

					if (temp_entry->type == LOGENTRY_SERVICE_DOWNTIME_STARTED)
						add_scheduled_downtime(AS_SVC_DOWNTIME_START, temp_entry->timestamp, temp_subject);
					else
						add_scheduled_downtime(AS_SVC_DOWNTIME_END, temp_entry->timestamp, temp_subject);

					break;

					/* scheduled host downtime notices */
				case LOGENTRY_HOST_DOWNTIME_STARTED:
				case LOGENTRY_HOST_DOWNTIME_STOPPED:
				case LOGENTRY_HOST_DOWNTIME_CANCELLED:

					/* get host name */
					temp_buffer = my_strtok(temp_entry->entry_text, ":");
					temp_buffer = my_strtok(NULL, ";");
					strncpy(entry_host_name, (temp_buffer == NULL) ? "" : temp_buffer + 1, sizeof(entry_host_name));
					entry_host_name[sizeof(entry_host_name)-1] = '\x0';

					/* this host downtime entry must be added to all service subjects associated with the host! */
					for (temp_subject = subject_list; temp_subject != NULL; temp_subject = temp_subject->next) {

						if (temp_subject->type != SERVICE_SUBJECT)
							break;

						if (strcmp(temp_subject->host_name, entry_host_name))
							break;

						if (show_scheduled_downtime == FALSE)
							break;

						if (temp_entry->type == LOGENTRY_HOST_DOWNTIME_STARTED)
							add_scheduled_downtime(AS_HOST_DOWNTIME_START, temp_entry->timestamp, temp_subject);
						else
							add_scheduled_downtime(AS_HOST_DOWNTIME_END, temp_entry->timestamp, temp_subject);
					}

					break;
				}
			}
		}
	}

	free_log_entries(&entry_list);

	return;
}


void compute_report_times(void) {
	time_t current_time;
	struct tm *st;
	struct tm *et;

	/* get the current time */
	time(&current_time);

	st = localtime(&current_time);

	st->tm_sec = start_second;
	st->tm_min = start_minute;
	st->tm_hour = start_hour;
	st->tm_mday = start_day;
	st->tm_mon = start_month - 1;
	st->tm_year = start_year - 1900;
	st->tm_isdst = -1;

	t1 = mktime(st);

	et = localtime(&current_time);

	et->tm_sec = end_second;
	et->tm_min = end_minute;
	et->tm_hour = end_hour;
	et->tm_mday = end_day;
	et->tm_mon = end_month - 1;
	et->tm_year = end_year - 1900;
	et->tm_isdst = -1;

	t2 = mktime(et);
}


/* writes log entries to screen */
void write_log_entries(avail_subject *subject) {
	archived_state *temp_as;
	archived_state *temp_sd;
	time_t current_time;
	time_t ts_end = 0L;
	char start_date_time[MAX_DATETIME_LENGTH];
	char end_date_time[MAX_DATETIME_LENGTH];
	char duration[20];
	char *bgclass = "";
	char *ebgclass = "";
	char *entry_type = "";
	char *state_type = "";
	int days;
	int hours;
	int minutes;
	int seconds;
	int odd = 0;
	int json_start = TRUE;


	if (content_type != HTML_CONTENT && content_type != JSON_CONTENT && content_type != XML_CONTENT)
		return;

	if (show_log_entries == FALSE)
		return;

	if (subject == NULL)
		return;

	time(&current_time);

	/* inject all scheduled downtime entries into the main list for display purposes */
	for (temp_sd = subject->sd_list; temp_sd != NULL; temp_sd = temp_sd->next) {
		switch (temp_sd->entry_type) {
		case AS_SVC_DOWNTIME_START:
		case AS_HOST_DOWNTIME_START:
			entry_type = "安排宕机开始";
			break;
		case AS_SVC_DOWNTIME_END:
		case AS_HOST_DOWNTIME_END:
			entry_type = "安排宕机结束";
			break;
		default:
			entry_type = "?";
			break;
		}
		add_archived_state(temp_sd->entry_type, AS_NO_DATA, temp_sd->time_stamp, entry_type, subject);
	}

	if (content_type == HTML_CONTENT) {
		printf("<BR><BR>\n");

		printf("<DIV ALIGN=CENTER CLASS='dataTitle'>%s日志记录:</DIV>\n", (subject->type == HOST_SUBJECT) ? "主机" : "服务");

		printf("<DIV ALIGN=CENTER CLASS='infoMessage'>");
		if (full_log_entries == TRUE) {
			full_log_entries = FALSE;
			if (subject->type == HOST_SUBJECT)
				host_report_url(subject->host_name, "[ 查看日志摘要记录 ]");
			else
				service_report_url(subject->host_name, subject->service_description, "[ 查看简明日志记录 ]");
			full_log_entries = TRUE;
		} else {
			full_log_entries = TRUE;
			if (subject->type == HOST_SUBJECT)
				host_report_url(subject->host_name, "[ 查看完整日志记录 ]");
			else
				service_report_url(subject->host_name, subject->service_description, "[ 查看完整日志记录 ]");
			full_log_entries = FALSE;
		}
		printf("</DIV>\n");

		printf("<table border=1 cellspacing=0 cellpadding=3 class='logEntries' align='center'>\n");
		printf("<tr><th class='logEntries'>事件开始时间</th><th class='logEntries'>事件结束时间</th><th class='logEntries'>事件持续时间</th><th class='logEntries'>事件/状态类型</th><th class='logEntries'>事件/状态信息</th></tr>\n");

	} else if (content_type == XML_CONTENT)
		printf("<log_entries>\n");
	else
		printf("\"log_entries\": [\n");


	/* write all archived state entries */
	for (temp_as = subject->as_list; temp_as != NULL; temp_as = temp_as->next) {

		if (temp_as->state_type == AS_HARD_STATE)
			state_type = " (硬件状态)";
		else if (temp_as->state_type == AS_SOFT_STATE)
			state_type = " (软件状态)";
		else
			state_type = "";

		switch (temp_as->entry_type) {
		case AS_NO_DATA:
			if (full_log_entries == FALSE)
				continue;
			entry_type = "无数据";
			ebgclass = "INDETERMINATE";
			break;
		case AS_PROGRAM_END:
			if (full_log_entries == FALSE)
				continue;
			entry_type = "程序结束";
			ebgclass = "INDETERMINATE";
			break;
		case AS_PROGRAM_START:
			if (full_log_entries == FALSE)
				continue;
			entry_type = "程序(重新)启动";
			ebgclass = "INDETERMINATE";
			break;
		case AS_HOST_UP:
			entry_type = "主机运行";
			ebgclass = "UP";
			break;
		case AS_HOST_DOWN:
			entry_type = "主机宕机";
			ebgclass = "DOWN";
			break;
		case AS_HOST_UNREACHABLE:
			entry_type = "主机不可达";
			ebgclass = "UNREACHABLE";
			break;
		case AS_SVC_OK:
			entry_type = "服务正常";
			ebgclass = "OK";
			break;
		case AS_SVC_UNKNOWN:
			entry_type = "服务未知";
			ebgclass = "UNKNOWN";
			break;
		case AS_SVC_WARNING:
			entry_type = "服务警报";
			ebgclass = "WARNING";
			break;
		case AS_SVC_CRITICAL:
			entry_type = "服务严重";
			ebgclass = "CRITICAL";
			break;
		case AS_SVC_DOWNTIME_START:
			entry_type = "服务宕机开始";
			ebgclass = "INDETERMINATE";
			break;
		case AS_SVC_DOWNTIME_END:
			entry_type = "服务宕机结束";
			ebgclass = "INDETERMINATE";
			break;
		case AS_HOST_DOWNTIME_START:
			entry_type = "主机宕机开始";
			ebgclass = "INDETERMINATE";
			break;
		case AS_HOST_DOWNTIME_END:
			entry_type = "主机宕机结束";
			ebgclass = "INDETERMINATE";
			break;
		default:
			if (full_log_entries == FALSE)
				continue;
			entry_type = "?";
			ebgclass = "INDETERMINATE";
		}

		get_time_string(&(temp_as->time_stamp), start_date_time, sizeof(start_date_time) - 1, SHORT_DATE_TIME);
		if (temp_as->next == NULL) {
			ts_end = t2;
			get_time_string(&t2, end_date_time, sizeof(end_date_time) - 1, SHORT_DATE_TIME);
			get_time_breakdown((time_t)(t2 - temp_as->time_stamp), &days, &hours, &minutes, &seconds);
			snprintf(duration, sizeof(duration) - 1, "%d天%d时%d分%d秒+", days, hours, minutes, seconds);
		} else {
			ts_end = temp_as->next->time_stamp;
			get_time_string(&(temp_as->next->time_stamp), end_date_time, sizeof(end_date_time) - 1, SHORT_DATE_TIME);
			get_time_breakdown((time_t)(temp_as->next->time_stamp - temp_as->time_stamp), &days, &hours, &minutes, &seconds);
			snprintf(duration, sizeof(duration) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		}

		if (odd) {
			bgclass = "Odd";
			odd = 0;
		} else {
			bgclass = "Even";
			odd = 1;
		}

		if (content_type == JSON_CONTENT) {
			if (json_start == FALSE)
				printf(",\n");
			json_start = FALSE;
			printf("{ \"开始时间的字符串\": \"%s\", ", start_date_time);
			printf(" \"开始时间的时间戳\": %lu, ", temp_as->time_stamp);
			printf(" \"结束时间的字符串\": \"%s\", ", end_date_time);
			printf(" \"结束时间的时间戳\": %lu, ", ts_end);
			printf(" \"持续时间的字符串\": \"%s\", ", duration);
			printf(" \"持续时间的时间戳\": %lu, ", (ts_end - temp_as->time_stamp));
			printf(" \"条目类型\": \"%s\", ", entry_type);
			printf(" \"状态类型\": \"");
			if (temp_as->state_type == AS_HARD_STATE)
				printf("硬状态");
			else if (temp_as->state_type == AS_SOFT_STATE)
				printf("软状态");
			printf("\", ");
			printf(" \"状态信息\": \"%s\"}", (temp_as->state_info == NULL) ? "" : json_encode(temp_as->state_info));

		} else if (content_type == XML_CONTENT) {
			printf("<log_entry>\n");
			printf("<start_time_string>%s</start_time_string>\n", start_date_time);
			printf("<start_time_timestamp>%lu</start_time_timestamp>\n", temp_as->time_stamp);
			printf("<end_time_string>%s</end_time_string>\n", end_date_time);
			printf("<end_time_timestamp>%lu</end_time_timestamp>\n", ts_end);
			printf("<duration_string>%s</duration_string>\n", duration);
			printf("<duration_timestamp>%lu</duration_timestamp>\n", (ts_end - temp_as->time_stamp));
			printf("<entry_type>%s</entry_type>\n", entry_type);
			printf("<state_type>");
			if (temp_as->state_type == AS_HARD_STATE)
				printf("硬件状态");
			else if (temp_as->state_type == AS_SOFT_STATE)
				printf("软件状态");
			printf("</state_type>\n");
			printf("<state_information>%s</state_information>\n", (temp_as->state_info == NULL) ? "" : temp_as->state_info);
			printf("</log_entry>\n");
		} else {
			printf("<tr class='logEntries%s'>", bgclass);
			printf("<td class='logEntries%s'>%s</td>", bgclass, start_date_time);
			printf("<td class='logEntries%s'>%s</td>", bgclass, end_date_time);
			printf("<td class='logEntries%s'>%s</td>", bgclass, duration);
			printf("<td class='logEntries%s'>%s%s</td>", ebgclass, entry_type, state_type);
			printf("<td class='logEntries%s'>%s</td>", bgclass, (temp_as->state_info == NULL) ? "" : html_encode(temp_as->state_info, FALSE));
			printf("</tr>\n");
		}
	}

	if (content_type == HTML_CONTENT)
		printf("</table>\n");
	else if (content_type == XML_CONTENT)
		printf("</log_entries>\n");
	else
		printf("\n]\n");

	return;
}



/* display hostgroup availability */
void display_hostgroup_availability(void) {
	hostgroup *temp_hostgroup;
	int json_start = TRUE;

	if (content_type == XML_CONTENT)
		printf("<hostgroup_availability>\n");
	else if (content_type == JSON_CONTENT)
		printf("\"主机组可用性\": {\n");

	/* display data for a specific hostgroup */
	if (show_all_hostgroups == FALSE) {
		temp_hostgroup = find_hostgroup(hostgroup_name);
		display_specific_hostgroup_availability(temp_hostgroup);

		/* display data for all hostgroups */
	} else {
		for (temp_hostgroup = hostgroup_list; temp_hostgroup != NULL; temp_hostgroup = temp_hostgroup->next) {
			if (content_type == JSON_CONTENT && json_start != TRUE)
				printf(",\n");
			json_start = FALSE;
			display_specific_hostgroup_availability(temp_hostgroup);
		}
	}

	if (content_type == XML_CONTENT)
		printf("</hostgroup_availability>\n");
	else if (content_type == JSON_CONTENT)
		printf("}\n");

	return;
}


/* display availability for a specific hostgroup */
void display_specific_hostgroup_availability(hostgroup *hg) {
	unsigned long total_time;
	unsigned long time_determinate;
	unsigned long time_indeterminate;
	avail_subject *temp_subject;
	host *temp_host;
	double percent_time_indeterminate = 0.0;
	double percent_time_up = 0.0;
	double percent_time_down = 0.0;
	double percent_time_unreachable = 0.0;
	double percent_time_up_known = 0.0;
	double percent_time_down_known = 0.0;
	double percent_time_unreachable_known = 0.0;

	double percent_time_up_scheduled = 0.0;
	double percent_time_up_unscheduled = 0.0;
	double percent_time_down_scheduled = 0.0;
	double percent_time_down_unscheduled = 0.0;
	double percent_time_unreachable_scheduled = 0.0;
	double percent_time_unreachable_unscheduled = 0.0;
	double percent_time_up_scheduled_known = 0.0;
	double percent_time_up_unscheduled_known = 0.0;
	double percent_time_down_scheduled_known = 0.0;
	double percent_time_down_unscheduled_known = 0.0;
	double percent_time_unreachable_scheduled_known = 0.0;
	double percent_time_unreachable_unscheduled_known = 0.0;

	double percent_time_indeterminate_notrunning = 0.0;
	double percent_time_indeterminate_nodata = 0.0;

	double average_percent_time_up = 0.0;
	double average_percent_time_up_known = 0.0;
	double average_percent_time_down = 0.0;
	double average_percent_time_down_known = 0.0;
	double average_percent_time_unreachable = 0.0;
	double average_percent_time_unreachable_known = 0.0;
	double average_percent_time_indeterminate = 0.0;

	int current_subject = 0;
	int i = 0;
	char *bgclass = "";
	int odd = 1;
	int json_start = TRUE;

	if (hg == NULL)
		return;

	/* the user isn't authorized to view this hostgroup */
	if (is_authorized_for_hostgroup(hg, &current_authdata) == FALSE)
		return;

	/* calculate total time during period based on timeperiod used for reporting */
	total_time = calculate_total_time(t1, t2);


	if (content_type == HTML_CONTENT) {
		printf("<BR><BR>\n");
		printf("<DIV ALIGN=CENTER CLASS='dataTitle'>主机组'%s'的主机状态细分:</DIV>\n", hg->group_name);
		printf("<TABLE BORDER=0 CLASS='data' align='center'>\n");
			printf("<TR><TH CLASS='data'>主机</TH><TH CLASS='data'>%% 运行时间</TH><TH CLASS='data'>%% 宕机时间</TH><TH CLASS='data'>%% 不可达时间</TH><TH CLASS='data'>%% 未决时间</TH></TR>\n");
	} else if (content_type == JSON_CONTENT) {
		printf("\"主机组\": {\n");
		printf("\"主机组名称\": \"%s\",\n", json_encode(hg->group_name));
		printf("\"主机\": [\n");
	} else if (content_type == XML_CONTENT) {
		printf("<hostgroup name=\"%s\">\n", hg->group_name);
	} else if (content_type == CSV_CONTENT) {
			printf("%s主机组%s主机状态细分%s%s\n", csv_data_enclosure, hg->group_name, csv_data_enclosure, csv_delimiter);

		for (i = 0; i < (hheader_num - 4); i++)
			printf("%s%s%s%s", csv_data_enclosure, hheader[i], csv_data_enclosure, csv_delimiter);

		printf("\n");
	}

	for (temp_subject = subject_list; temp_subject != NULL; temp_subject = temp_subject->next) {

		if (temp_subject->type != HOST_SUBJECT)
			continue;

		temp_host = find_host(temp_subject->host_name);
		if (temp_host == NULL)
			continue;

		if (is_host_member_of_hostgroup(hg, temp_host) == FALSE)
			continue;

		current_subject++;

		/* reset variables */
		percent_time_up = 0.0;
		percent_time_down = 0.0;
		percent_time_unreachable = 0.0;
		percent_time_indeterminate = 0.0;
		percent_time_up_known = 0.0;
		percent_time_down_known = 0.0;
		percent_time_unreachable_known = 0.0;

		time_determinate = temp_subject->time_up + temp_subject->time_down + temp_subject->time_unreachable;
		time_indeterminate = total_time - time_determinate;

		if (total_time > 0) {
			percent_time_up = (double)(((double)temp_subject->time_up * 100.0) / (double)total_time);
			percent_time_down = (double)(((double)temp_subject->time_down * 100.0) / (double)total_time);
			percent_time_unreachable = (double)(((double)temp_subject->time_unreachable * 100.0) / (double)total_time);
			percent_time_indeterminate = (double)(((double)time_indeterminate * 100.0) / (double)total_time);
			if (time_determinate > 0) {
				percent_time_up_known = (double)(((double)temp_subject->time_up * 100.0) / (double)time_determinate);
				percent_time_down_known = (double)(((double)temp_subject->time_down * 100.0) / (double)time_determinate);
				percent_time_unreachable_known = (double)(((double)temp_subject->time_unreachable * 100.0) / (double)time_determinate);
			}
		}

		if (odd) {
			odd = 0;
			bgclass = "Odd";
		} else {
			odd = 1;
			bgclass = "Even";
		}

		if (content_type == HTML_CONTENT) {

			printf("<tr CLASS='data%s'><td CLASS='data%s'>", bgclass, bgclass);
			host_report_url(temp_subject->host_name, temp_subject->host_name);
			printf("</td><td CLASS='hostUP'>%2.3f%% (%2.3f%%)</td><td CLASS='hostDOWN'>%2.3f%% (%2.3f%%)</td><td CLASS='hostUNREACHABLE'>%2.3f%% (%2.3f%%)</td><td class='data%s' align='center'>%2.3f%%</td></tr>\n", percent_time_up, percent_time_up_known, percent_time_down, percent_time_down_known, percent_time_unreachable, percent_time_unreachable_known, bgclass, percent_time_indeterminate);

		} else if (content_type == JSON_CONTENT) {
			if (json_start != TRUE)
				printf(",\n");

			/* host name */
			printf("{ \"%s\": \"%s\", ", hheader[0], json_encode(temp_subject->host_name));
			printf("{ \"%s\": \"%s\", ", hheader[37], (temp_host->display_name != NULL) ? json_encode(temp_host->display_name) : json_encode(temp_host->name));

			/* up times */
			printf(" \"%s\": %lu, ", hheader[1], temp_subject->scheduled_time_up);
			printf(" \"%s\": %2.3f, ", hheader[2], percent_time_up_scheduled);
			printf(" \"%s\": %2.3f, ", hheader[3], percent_time_up_scheduled_known);
			printf(" \"%s\": %lu, ", hheader[4], temp_subject->time_up - temp_subject->scheduled_time_up);
			printf(" \"%s\": %2.3f, ", hheader[5], percent_time_up_unscheduled);
			printf(" \"%s\": %2.3f, ", hheader[6], percent_time_up_unscheduled_known);
			printf(" \"%s\": %lu, ", hheader[7], temp_subject->time_up);
			printf(" \"%s\": %2.3f, ", hheader[8], percent_time_up);
			printf(" \"%s\": %2.3f, ", hheader[9], percent_time_up_known);

			/* down times */
			printf(" \"%s\": %lu, ", hheader[10], temp_subject->scheduled_time_down);
			printf(" \"%s\": %2.3f, ", hheader[11], percent_time_down_scheduled);
			printf(" \"%s\": %2.3f, ", hheader[12], percent_time_down_scheduled_known);
			printf(" \"%s\": %lu, ", hheader[13], temp_subject->time_down - temp_subject->scheduled_time_down);
			printf(" \"%s\": %2.3f, ", hheader[14], percent_time_down_unscheduled);
			printf(" \"%s\": %2.3f, ", hheader[15], percent_time_down_unscheduled_known);
			printf(" \"%s\": %lu, ", hheader[16], temp_subject->time_down);
			printf(" \"%s\": %2.3f, ", hheader[17], percent_time_down);
			printf(" \"%s\": %2.3f, ", hheader[18], percent_time_down_known);

			/* unreachable times */
			printf(" \"%s\": %lu, ", hheader[19], temp_subject->scheduled_time_unreachable);
			printf(" \"%s\": %2.3f, ", hheader[20], percent_time_unreachable_scheduled);
			printf(" \"%s\": %2.3f, ", hheader[21], percent_time_unreachable_scheduled_known);
			printf(" \"%s\": %lu, ", hheader[22], temp_subject->time_unreachable - temp_subject->scheduled_time_unreachable);
			printf(" \"%s\": %2.3f, ", hheader[23], percent_time_unreachable_unscheduled);
			printf(" \"%s\": %2.3f, ", hheader[24], percent_time_unreachable_unscheduled_known);
			printf(" \"%s\": %lu, ", hheader[25], temp_subject->time_unreachable);
			printf(" \"%s\": %2.3f, ", hheader[26], percent_time_unreachable);
			printf(" \"%s\": %2.3f, ", hheader[27], percent_time_unreachable_known);

			/* indeterminate times */
			printf(" \"%s\": %lu, ", hheader[28], temp_subject->time_indeterminate_notrunning);
			printf(" \"%s\": %2.3f, ", hheader[29], percent_time_indeterminate_notrunning);
			printf(" \"%s\": %lu, ", hheader[30], temp_subject->time_indeterminate_nodata);
			printf(" \"%s\": %2.3f, ", hheader[31], percent_time_indeterminate_nodata);
			printf(" \"%s\": %lu, ", hheader[32], time_indeterminate);
			printf(" \"%s\": %2.3f} ", hheader[33], percent_time_indeterminate);

			json_start = FALSE;

		} else if (content_type == XML_CONTENT) {

			printf("<host name=\"%s\">\n", temp_subject->host_name);

			/* up times */
			printf("<%s>%lu</%s>\n", hheader[1], temp_subject->scheduled_time_up, hheader[1]);
			printf("<%s>%2.3f</%s>\n", hheader[2], percent_time_up_scheduled, hheader[2]);
			printf("<%s>%2.3f</%s>\n", hheader[3], percent_time_up_scheduled_known, hheader[3]);
			printf("<%s>%lu</%s>\n", hheader[4], temp_subject->time_up - temp_subject->scheduled_time_up, hheader[4]);
			printf("<%s>%2.3f</%s>\n", hheader[5], percent_time_up_unscheduled, hheader[5]);
			printf("<%s>%2.3f</%s>\n", hheader[6], percent_time_up_unscheduled_known, hheader[6]);
			printf("<%s>%lu</%s>\n", hheader[7], temp_subject->time_up, hheader[7]);
			printf("<%s>%2.3f</%s>\n", hheader[8], percent_time_up, hheader[8]);
			printf("<%s>%2.3f</%s>\n", hheader[9], percent_time_up_known, hheader[9]);

			/* down times */
			printf("<%s>%lu</%s>\n", hheader[10], temp_subject->scheduled_time_down, hheader[10]);
			printf("<%s>%2.3f</%s>\n", hheader[11], percent_time_down_scheduled, hheader[11]);
			printf("<%s>%2.3f</%s>\n", hheader[12], percent_time_down_scheduled_known, hheader[12]);
			printf("<%s>%lu</%s>\n", hheader[13], temp_subject->time_down - temp_subject->scheduled_time_down, hheader[13]);
			printf("<%s>%2.3f</%s>\n", hheader[14], percent_time_down_unscheduled, hheader[14]);
			printf("<%s>%2.3f</%s>\n", hheader[15], percent_time_down_unscheduled_known, hheader[15]);
			printf("<%s>%lu</%s>\n", hheader[16], temp_subject->time_down, hheader[16]);
			printf("<%s>%2.3f</%s>\n", hheader[17], percent_time_down, hheader[17]);
			printf("<%s>%2.3f</%s>\n", hheader[18], percent_time_down_known, hheader[18]);

			/* unreachable times */
			printf("<%s>%lu</%s>\n", hheader[19], temp_subject->scheduled_time_unreachable, hheader[19]);
			printf("<%s>%2.3f</%s>\n", hheader[20], percent_time_unreachable_scheduled, hheader[20]);
			printf("<%s>%2.3f</%s>\n", hheader[21], percent_time_unreachable_scheduled_known, hheader[21]);
			printf("<%s>%lu</%s>\n", hheader[22], temp_subject->time_unreachable - temp_subject->scheduled_time_unreachable, hheader[22]);
			printf("<%s>%2.3f</%s>\n", hheader[23], percent_time_unreachable_unscheduled, hheader[23]);
			printf("<%s>%2.3f</%s>\n", hheader[24], percent_time_unreachable_unscheduled_known, hheader[24]);
			printf("<%s>%lu</%s>\n", hheader[25], temp_subject->time_unreachable, hheader[25]);
			printf("<%s>%2.3f</%s>\n", hheader[26], percent_time_unreachable, hheader[26]);
			printf("<%s>%2.3f</%s>\n", hheader[27], percent_time_unreachable_known, hheader[27]);

			/* indeterminate times */
			printf("<%s>%lu</%s>\n", hheader[28], temp_subject->time_indeterminate_notrunning, hheader[28]);
			printf("<%s>%2.3f</%s>\n", hheader[29], percent_time_indeterminate_notrunning, hheader[29]);
			printf("<%s>%lu</%s>\n", hheader[30], temp_subject->time_indeterminate_nodata, hheader[30]);
			printf("<%s>%2.3f</%s>\n", hheader[31], percent_time_indeterminate_nodata, hheader[31]);
			printf("<%s>%lu</%s>\n", hheader[32], time_indeterminate, hheader[32]);
			printf("<%s>%2.3f</%s>\n", hheader[33], percent_time_indeterminate, hheader[33]);

			printf("</host>\n");

		} else if (content_type == CSV_CONTENT) {

			/* host name */
			printf("%s%s%s%s", csv_data_enclosure, temp_subject->host_name, csv_data_enclosure, csv_delimiter);

			/* up times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_up, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_scheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_scheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_up - temp_subject->scheduled_time_up, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_unscheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_unscheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_up, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_known, csv_data_enclosure, csv_delimiter);

			/* down times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_down, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_scheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_scheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_down - temp_subject->scheduled_time_down, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_unscheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_unscheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_down, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_known, csv_data_enclosure, csv_delimiter);

			/* unreachable times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_unreachable, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_scheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_scheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_unreachable - temp_subject->scheduled_time_unreachable, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_unscheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_unscheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_unreachable, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_known, csv_data_enclosure, csv_delimiter);

			/* indeterminate times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_indeterminate_notrunning, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate_notrunning, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_indeterminate_nodata, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate_nodata, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, time_indeterminate, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate, csv_data_enclosure, csv_delimiter);

			printf("\n");
		}

		get_running_average(&average_percent_time_up, percent_time_up, current_subject);
		get_running_average(&average_percent_time_up_known, percent_time_up_known, current_subject);
		get_running_average(&average_percent_time_down, percent_time_down, current_subject);
		get_running_average(&average_percent_time_down_known, percent_time_down_known, current_subject);
		get_running_average(&average_percent_time_unreachable, percent_time_unreachable, current_subject);
		get_running_average(&average_percent_time_unreachable_known, percent_time_unreachable_known, current_subject);
		get_running_average(&average_percent_time_indeterminate, percent_time_indeterminate, current_subject);
	}


	/* average statistics */
	if (odd) {
		odd = 0;
		bgclass = "Odd";
	} else {
		odd = 1;
		bgclass = "Even";
	}

	if (content_type == HTML_CONTENT) {
		printf("<tr CLASS='data%s'><td CLASS='data%s'>平均</td><td CLASS='hostUP'>%2.3f%% (%2.3f%%)</td><td CLASS='hostDOWN'>%2.3f%% (%2.3f%%)</td><td CLASS='hostUNREACHABLE'>%2.3f%% (%2.3f%%)</td><td class='data%s' align='center'>%2.3f%%</td></tr>", bgclass, bgclass, average_percent_time_up, average_percent_time_up_known, average_percent_time_down, average_percent_time_down_known, average_percent_time_unreachable, average_percent_time_unreachable_known, bgclass, average_percent_time_indeterminate);
		printf("</table>\n");
	} else if (content_type == JSON_CONTENT) {
		printf("],\n");
		printf("\"所有主机的平均值\": [ {");
		printf("\"运行时间平均百分比\": %2.3f, ", average_percent_time_up);
		printf("\"已知运行时间平均百分比\": %2.3f, ", average_percent_time_up_known);
		printf("\"宕机时间平均百分比\": %2.3f, ", average_percent_time_down);
		printf("\"已知宕机时间平均百分比\": %2.3f, ", average_percent_time_down_known);
		printf("\"不可达时间平均百分比\": %2.3f, ", average_percent_time_unreachable);
		printf("\"已知不可达时间平均百分比\": %2.3f, ", average_percent_time_unreachable_known);
		printf("\"未决时间平均百分比\": %2.3f } ] }\n", average_percent_time_indeterminate);
	} else if (content_type == XML_CONTENT) {
		printf("<all_hosts_average>\n");
		printf("<average_percent_time_up>%2.3f</average_percent_time_up>\n", average_percent_time_up);
		printf("<average_percent_time_up_known>%2.3f</average_percent_time_up_known>\n", average_percent_time_up_known);
		printf("<average_percent_time_down>%2.3f</average_percent_time_down>\n", average_percent_time_down);
		printf("<average_percent_time_down_known>%2.3f</average_percent_time_down_known>\n", average_percent_time_down_known);
		printf("<average_percent_time_unreachable>%2.3f</average_percent_time_unreachable>\n", average_percent_time_unreachable);
		printf("<average_percent_time_unreachable_known>%2.3f</average_percent_time_unreachable_known>\n", average_percent_time_unreachable_known);
		printf("<average_percent_time_indeterminate>%2.3f</average_percent_time_indeterminate>\n", average_percent_time_indeterminate);
		printf("</all_hosts_average>\n");
		printf("</hostgroup>\n");
	} else if (content_type == CSV_CONTENT) {
		/* average */
		/* left for future rework */
	}

	return;
}


/* display servicegroup availability */
void display_servicegroup_availability(void) {
	servicegroup *temp_servicegroup;
	int json_start = TRUE;

	if (content_type == XML_CONTENT)
		printf("<servicegroup_availability>\n");
	else if (content_type == JSON_CONTENT)
		printf("\"服务组可用性\": {\n");

	/* display data for a specific servicegroup */
	if (show_all_servicegroups == FALSE) {
		temp_servicegroup = find_servicegroup(servicegroup_name);
		display_specific_servicegroup_availability(temp_servicegroup);

		/* display data for all servicegroups */
	} else {
		for (temp_servicegroup = servicegroup_list; temp_servicegroup != NULL; temp_servicegroup = temp_servicegroup->next) {
			if (content_type == JSON_CONTENT && json_start != TRUE)
				printf(",\n");
			json_start = FALSE;
			display_specific_servicegroup_availability(temp_servicegroup);
		}
	}

	if (content_type == XML_CONTENT)
		printf("</servicegroup_availability>\n");
	else if (content_type == JSON_CONTENT)
		printf("}\n");

	return;
}



/* display availability for a specific servicegroup */
void display_specific_servicegroup_availability(servicegroup *sg) {
	unsigned long total_time;
	unsigned long time_determinate;
	unsigned long time_indeterminate;
	avail_subject *temp_subject;
	service *temp_service;
	host *temp_host;
	double percent_time_ok = 0.0;
	double percent_time_warning = 0.0;
	double percent_time_unknown = 0.0;
	double percent_time_critical = 0.0;
	double percent_time_indeterminate = 0.0;
	double percent_time_ok_known = 0.0;
	double percent_time_warning_known = 0.0;
	double percent_time_unknown_known = 0.0;
	double percent_time_critical_known = 0.0;

	double percent_time_critical_scheduled = 0.0;
	double percent_time_critical_unscheduled = 0.0;
	double percent_time_critical_scheduled_known = 0.0;
	double percent_time_critical_unscheduled_known = 0.0;
	double percent_time_unknown_scheduled = 0.0;
	double percent_time_unknown_unscheduled = 0.0;
	double percent_time_unknown_scheduled_known = 0.0;
	double percent_time_unknown_unscheduled_known = 0.0;
	double percent_time_warning_scheduled = 0.0;
	double percent_time_warning_unscheduled = 0.0;
	double percent_time_warning_scheduled_known = 0.0;
	double percent_time_warning_unscheduled_known = 0.0;
	double percent_time_ok_scheduled = 0.0;
	double percent_time_ok_unscheduled = 0.0;
	double percent_time_ok_scheduled_known = 0.0;
	double percent_time_ok_unscheduled_known = 0.0;

	double percent_time_up = 0.0;
	double percent_time_down = 0.0;
	double percent_time_unreachable = 0.0;
	double percent_time_up_known = 0.0;
	double percent_time_down_known = 0.0;
	double percent_time_unreachable_known = 0.0;
	double percent_time_up_scheduled = 0.0;
	double percent_time_up_unscheduled = 0.0;
	double percent_time_down_scheduled = 0.0;
	double percent_time_down_unscheduled = 0.0;
	double percent_time_unreachable_scheduled = 0.0;
	double percent_time_unreachable_unscheduled = 0.0;
	double percent_time_up_scheduled_known = 0.0;
	double percent_time_up_unscheduled_known = 0.0;
	double percent_time_down_scheduled_known = 0.0;
	double percent_time_down_unscheduled_known = 0.0;
	double percent_time_unreachable_scheduled_known = 0.0;
	double percent_time_unreachable_unscheduled_known = 0.0;

	double average_percent_time_up = 0.0;
	double average_percent_time_up_known = 0.0;
	double average_percent_time_down = 0.0;
	double average_percent_time_down_known = 0.0;
	double average_percent_time_unreachable = 0.0;
	double average_percent_time_unreachable_known = 0.0;

	double average_percent_time_ok = 0.0;
	double average_percent_time_ok_known = 0.0;
	double average_percent_time_unknown = 0.0;
	double average_percent_time_unknown_known = 0.0;
	double average_percent_time_warning = 0.0;
	double average_percent_time_warning_known = 0.0;
	double average_percent_time_critical = 0.0;
	double average_percent_time_critical_known = 0.0;
	double average_percent_time_indeterminate = 0.0;

	int current_subject = 0;

	double percent_time_indeterminate_notrunning = 0.0;
	double percent_time_indeterminate_nodata = 0.0;

	int odd = 1;
	int i = 0;
	char *bgclass = "";
	char last_host[128] = "";
	int json_start = TRUE;

	if (sg == NULL)
		return;

	/* the user isn't authorized to view this servicegroup */
	if (is_authorized_for_servicegroup(sg, &current_authdata) == FALSE)
		return;

	/* calculate total time during period based on timeperiod used for reporting */
	total_time = calculate_total_time(t1, t2);

	if (content_type == HTML_CONTENT) {
		printf("<BR><BR>\n");
		printf("<DIV ALIGN=CENTER CLASS='dataTitle'>服务组'%s'的主机状态细分:</DIV>\n", sg->group_name);
		printf("<TABLE BORDER=0 CLASS='data' align='center'>\n");
		printf("<TR><TH CLASS='data'>主机</TH><TH CLASS='data'>%% 运行时间</TH><TH CLASS='data'>%% 宕机时间</TH><TH CLASS='data'>%% 不可达时间</TH><TH CLASS='data'>%% 未决时间</TH></TR>\n");
	} else if (content_type == XML_CONTENT) {
		printf("<servicegroup name=\"%s\">\n", sg->group_name);
		printf("<hosts>\n");
	} else if (content_type == JSON_CONTENT) {
		printf("\"服务组\": {\n");
		printf("\"服务组名称\": \"%s\",\n", json_encode(sg->group_name));
		printf("\"hosts\": [\n");
	} else if (content_type == CSV_CONTENT) {
		printf("%s服务组%s主机状态细分%s%s\n", csv_data_enclosure, sg->group_name, csv_data_enclosure, csv_delimiter);

		for (i = 0; i < (hheader_num - 4); i++)
			printf("%s%s%s%s", csv_data_enclosure, hheader[i], csv_data_enclosure, csv_delimiter);

		printf("\n");
	}

	for (temp_subject = subject_list; temp_subject != NULL; temp_subject = temp_subject->next) {

		if (temp_subject->type != HOST_SUBJECT)
			continue;

		temp_host = find_host(temp_subject->host_name);
		if (temp_host == NULL)
			continue;

		if (is_host_member_of_servicegroup(sg, temp_host) == FALSE)
			continue;

		current_subject++;

		/* reset variables */
		percent_time_up = 0.0;
		percent_time_down = 0.0;
		percent_time_unreachable = 0.0;
		percent_time_indeterminate = 0.0;
		percent_time_up_known = 0.0;
		percent_time_down_known = 0.0;
		percent_time_unreachable_known = 0.0;

		time_determinate = temp_subject->time_up + temp_subject->time_down + temp_subject->time_unreachable;
		time_indeterminate = total_time - time_determinate;

		if (total_time > 0) {
			percent_time_up = (double)(((double)temp_subject->time_up * 100.0) / (double)total_time);
			percent_time_down = (double)(((double)temp_subject->time_down * 100.0) / (double)total_time);
			percent_time_unreachable = (double)(((double)temp_subject->time_unreachable * 100.0) / (double)total_time);
			percent_time_indeterminate = (double)(((double)time_indeterminate * 100.0) / (double)total_time);
			if (time_determinate > 0) {
				percent_time_up_known = (double)(((double)temp_subject->time_up * 100.0) / (double)time_determinate);
				percent_time_down_known = (double)(((double)temp_subject->time_down * 100.0) / (double)time_determinate);
				percent_time_unreachable_known = (double)(((double)temp_subject->time_unreachable * 100.0) / (double)time_determinate);
			}
		}

		if (odd) {
			odd = 0;
			bgclass = "Odd";
		} else {
			odd = 1;
			bgclass = "Even";
		}

		if (content_type == HTML_CONTENT) {

			printf("<tr CLASS='data%s'><td CLASS='data%s'>", bgclass, bgclass);
			host_report_url(temp_subject->host_name, temp_subject->host_name);
			printf("</td><td CLASS='hostUP'>%2.3f%% (%2.3f%%)</td><td CLASS='hostDOWN'>%2.3f%% (%2.3f%%)</td><td CLASS='hostUNREACHABLE'>%2.3f%% (%2.3f%%)</td><td class='data%s' align='center'>%2.3f%%</td></tr>\n", percent_time_up, percent_time_up_known, percent_time_down, percent_time_down_known, percent_time_unreachable, percent_time_unreachable_known, bgclass, percent_time_indeterminate);

		} else if (content_type == JSON_CONTENT) {
			if (json_start != TRUE)
				printf(",\n");

			/* host name */
			printf("{ \"%s\": \"%s\", ", hheader[0], json_encode(temp_subject->host_name));
			printf("{ \"%s\": \"%s\", ", hheader[37], (temp_host->display_name != NULL) ? json_encode(temp_host->display_name) : json_encode(temp_host->name));

			/* up times */
			printf(" \"%s\": %lu, ", hheader[1], temp_subject->scheduled_time_up);
			printf(" \"%s\": %2.3f, ", hheader[2], percent_time_up_scheduled);
			printf(" \"%s\": %2.3f, ", hheader[3], percent_time_up_scheduled_known);
			printf(" \"%s\": %lu, ", hheader[4], temp_subject->time_up - temp_subject->scheduled_time_up);
			printf(" \"%s\": %2.3f, ", hheader[5], percent_time_up_unscheduled);
			printf(" \"%s\": %2.3f, ", hheader[6], percent_time_up_unscheduled_known);
			printf(" \"%s\": %lu, ", hheader[7], temp_subject->time_up);
			printf(" \"%s\": %2.3f, ", hheader[8], percent_time_up);
			printf(" \"%s\": %2.3f, ", hheader[9], percent_time_up_known);

			/* down times */
			printf(" \"%s\": %lu, ", hheader[10], temp_subject->scheduled_time_down);
			printf(" \"%s\": %2.3f, ", hheader[11], percent_time_down_scheduled);
			printf(" \"%s\": %2.3f, ", hheader[12], percent_time_down_scheduled_known);
			printf(" \"%s\": %lu, ", hheader[13], temp_subject->time_down - temp_subject->scheduled_time_down);
			printf(" \"%s\": %2.3f, ", hheader[14], percent_time_down_unscheduled);
			printf(" \"%s\": %2.3f, ", hheader[15], percent_time_down_unscheduled_known);
			printf(" \"%s\": %lu, ", hheader[16], temp_subject->time_down);
			printf(" \"%s\": %2.3f, ", hheader[17], percent_time_down);
			printf(" \"%s\": %2.3f, ", hheader[18], percent_time_down_known);

			/* unreachable times */
			printf(" \"%s\": %lu, ", hheader[19], temp_subject->scheduled_time_unreachable);
			printf(" \"%s\": %2.3f, ", hheader[20], percent_time_unreachable_scheduled);
			printf(" \"%s\": %2.3f, ", hheader[21], percent_time_unreachable_scheduled_known);
			printf(" \"%s\": %lu, ", hheader[22], temp_subject->time_unreachable - temp_subject->scheduled_time_unreachable);
			printf(" \"%s\": %2.3f, ", hheader[23], percent_time_unreachable_unscheduled);
			printf(" \"%s\": %2.3f, ", hheader[24], percent_time_unreachable_unscheduled_known);
			printf(" \"%s\": %lu, ", hheader[25], temp_subject->time_unreachable);
			printf(" \"%s\": %2.3f, ", hheader[26], percent_time_unreachable);
			printf(" \"%s\": %2.3f, ", hheader[27], percent_time_unreachable_known);

			/* indeterminate times */
			printf(" \"%s\": %lu, ", hheader[28], temp_subject->time_indeterminate_notrunning);
			printf(" \"%s\": %2.3f, ", hheader[29], percent_time_indeterminate_notrunning);
			printf(" \"%s\": %lu, ", hheader[30], temp_subject->time_indeterminate_nodata);
			printf(" \"%s\": %2.3f, ", hheader[31], percent_time_indeterminate_nodata);
			printf(" \"%s\": %lu, ", hheader[32], time_indeterminate);
			printf(" \"%s\": %2.3f} ", hheader[33], percent_time_indeterminate);

			json_start = FALSE;

		} else if (content_type == XML_CONTENT) {

			printf("<host name=\"%s\">\n", temp_subject->host_name);

			/* up times */
			printf("<%s>%lu</%s>\n", hheader[1], temp_subject->scheduled_time_up, hheader[1]);
			printf("<%s>%2.3f</%s>\n", hheader[2], percent_time_up_scheduled, hheader[2]);
			printf("<%s>%2.3f</%s>\n", hheader[3], percent_time_up_scheduled_known, hheader[3]);
			printf("<%s>%lu</%s>\n", hheader[4], temp_subject->time_up - temp_subject->scheduled_time_up, hheader[4]);
			printf("<%s>%2.3f</%s>\n", hheader[5], percent_time_up_unscheduled, hheader[5]);
			printf("<%s>%2.3f</%s>\n", hheader[6], percent_time_up_unscheduled_known, hheader[6]);
			printf("<%s>%lu</%s>\n", hheader[7], temp_subject->time_up, hheader[7]);
			printf("<%s>%2.3f</%s>\n", hheader[8], percent_time_up, hheader[8]);
			printf("<%s>%2.3f</%s>\n", hheader[9], percent_time_up_known, hheader[9]);

			/* down times */
			printf("<%s>%lu</%s>\n", hheader[10], temp_subject->scheduled_time_down, hheader[10]);
			printf("<%s>%2.3f</%s>\n", hheader[11], percent_time_down_scheduled, hheader[11]);
			printf("<%s>%2.3f</%s>\n", hheader[12], percent_time_down_scheduled_known, hheader[12]);
			printf("<%s>%lu</%s>\n", hheader[13], temp_subject->time_down - temp_subject->scheduled_time_down, hheader[13]);
			printf("<%s>%2.3f</%s>\n", hheader[14], percent_time_down_unscheduled, hheader[14]);
			printf("<%s>%2.3f</%s>\n", hheader[15], percent_time_down_unscheduled_known, hheader[15]);
			printf("<%s>%lu</%s>\n", hheader[16], temp_subject->time_down, hheader[16]);
			printf("<%s>%2.3f</%s>\n", hheader[17], percent_time_down, hheader[17]);
			printf("<%s>%2.3f</%s>\n", hheader[18], percent_time_down_known, hheader[18]);

			/* unreachable times */
			printf("<%s>%lu</%s>\n", hheader[19], temp_subject->scheduled_time_unreachable, hheader[19]);
			printf("<%s>%2.3f</%s>\n", hheader[20], percent_time_unreachable_scheduled, hheader[20]);
			printf("<%s>%2.3f</%s>\n", hheader[21], percent_time_unreachable_scheduled_known, hheader[21]);
			printf("<%s>%lu</%s>\n", hheader[22], temp_subject->time_unreachable - temp_subject->scheduled_time_unreachable, hheader[22]);
			printf("<%s>%2.3f</%s>\n", hheader[23], percent_time_unreachable_unscheduled, hheader[23]);
			printf("<%s>%2.3f</%s>\n", hheader[24], percent_time_unreachable_unscheduled_known, hheader[24]);
			printf("<%s>%lu</%s>\n", hheader[25], temp_subject->time_unreachable, hheader[25]);
			printf("<%s>%2.3f</%s>\n", hheader[26], percent_time_unreachable, hheader[26]);
			printf("<%s>%2.3f</%s>\n", hheader[27], percent_time_unreachable_known, hheader[27]);

			/* indeterminate times */
			printf("<%s>%lu</%s>\n", hheader[28], temp_subject->time_indeterminate_notrunning, hheader[28]);
			printf("<%s>%2.3f</%s>\n", hheader[29], percent_time_indeterminate_notrunning, hheader[29]);
			printf("<%s>%lu</%s>\n", hheader[30], temp_subject->time_indeterminate_nodata, hheader[30]);
			printf("<%s>%2.3f</%s>\n", hheader[31], percent_time_indeterminate_nodata, hheader[31]);
			printf("<%s>%lu</%s>\n", hheader[32], time_indeterminate, hheader[32]);
			printf("<%s>%2.3f</%s>\n", hheader[33], percent_time_indeterminate, hheader[33]);

			printf("</host>\n");

		} else if (content_type == CSV_CONTENT) {
			/* host name */
			printf("%s%s%s%s", csv_data_enclosure, temp_subject->host_name, csv_data_enclosure, csv_delimiter);

			/* up times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_up, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_scheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_scheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_up - temp_subject->scheduled_time_up, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_unscheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_unscheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_up, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_known, csv_data_enclosure, csv_delimiter);

			/* down times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_down, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_scheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_scheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_down - temp_subject->scheduled_time_down, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_unscheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_unscheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_down, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_known, csv_data_enclosure, csv_delimiter);

			/* unreachable times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_unreachable, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_scheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_scheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_unreachable - temp_subject->scheduled_time_unreachable, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_unscheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_unscheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_unreachable, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_known, csv_data_enclosure, csv_delimiter);

			/* indeterminate times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_indeterminate_notrunning, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate_notrunning, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_indeterminate_nodata, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate_nodata, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, time_indeterminate, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate, csv_data_enclosure, csv_delimiter);

			printf("\n");
		}

		get_running_average(&average_percent_time_up, percent_time_up, current_subject);
		get_running_average(&average_percent_time_up_known, percent_time_up_known, current_subject);
		get_running_average(&average_percent_time_down, percent_time_down, current_subject);
		get_running_average(&average_percent_time_down_known, percent_time_down_known, current_subject);
		get_running_average(&average_percent_time_unreachable, percent_time_unreachable, current_subject);
		get_running_average(&average_percent_time_unreachable_known, percent_time_unreachable_known, current_subject);
		get_running_average(&average_percent_time_indeterminate, percent_time_indeterminate, current_subject);
	}

	/* average statistics */
	if (odd) {
		odd = 0;
		bgclass = "Odd";
	} else {
		odd = 1;
		bgclass = "Even";
	}

	if (content_type == HTML_CONTENT) {

		printf("<tr CLASS='data%s'><td CLASS='data%s'>平均</td><td CLASS='hostUP'>%2.3f%% (%2.3f%%)</td><td CLASS='hostDOWN'>%2.3f%% (%2.3f%%)</td><td CLASS='hostUNREACHABLE'>%2.3f%% (%2.3f%%)</td><td class='data%s' align='center'>%2.3f%%</td></tr>", bgclass, bgclass, average_percent_time_up, average_percent_time_up_known, average_percent_time_down, average_percent_time_down_known, average_percent_time_unreachable, average_percent_time_unreachable_known, bgclass, average_percent_time_indeterminate);

		printf("</table>\n");

		printf("<BR>\n");
		printf("<DIV ALIGN=CENTER CLASS='dataTitle'>服务组'%s'的服务状态细分:</DIV>\n", sg->group_name);

		printf("<TABLE BORDER=0 CLASS='data' align='center'>\n");
		printf("<TR><TH CLASS='data'>主机</TH><TH CLASS='data'>服务</TH><TH CLASS='data'>%% 正常时间</TH><TH CLASS='data'>%% 警报时间</TH><TH CLASS='data'>%% 未知时间</TH><TH CLASS='data'>%% 严重时间</TH><TH CLASS='data'>%% 未决时间</TH></TR>\n");
	} else if (content_type == JSON_CONTENT) {
		printf(" ],\n");
		printf("\"所有主机的平均值\": [ {");
		printf("\"运行时间平均百分比\": %2.3f, ", average_percent_time_up);
		printf("\"已知运行时间平均百分比\": %2.3f, ", average_percent_time_up_known);
		printf("\"宕机时间平均百分比\": %2.3f, ", average_percent_time_down);
		printf("\"已知宕机时间平均百分比\": %2.3f, ", average_percent_time_down_known);
		printf("\"不可达时间平均百分比\": %2.3f, ", average_percent_time_unreachable);
		printf("\"已知不可达时间平均百分比\": %2.3f, ", average_percent_time_unreachable_known);
		printf("\"未决时间平均百分比\": %2.3f } ],\n", average_percent_time_indeterminate);
		printf("\"服务\": [\n");
		json_start = TRUE;
	} else if (content_type == XML_CONTENT) {
		printf("<all_hosts_average>\n");
		printf("<average_percent_time_up>%2.3f</average_percent_time_up>\n", average_percent_time_up);
		printf("<average_percent_time_up_known>%2.3f</average_percent_time_up_known>\n", average_percent_time_up_known);
		printf("<average_percent_time_down>%2.3f</average_percent_time_down>\n", average_percent_time_down);
		printf("<average_percent_time_down_known>%2.3f</average_percent_time_down_known>\n", average_percent_time_down_known);
		printf("<average_percent_time_unreachable>%2.3f</average_percent_time_unreachable>\n", average_percent_time_unreachable);
		printf("<average_percent_time_unreachable_known>%2.3f</average_percent_time_unreachable_known>\n", average_percent_time_unreachable_known);
		printf("<average_percent_time_indeterminate>%2.3f</average_percent_time_indeterminate>\n", average_percent_time_indeterminate);
		printf("</all_hosts_average>\n");
		printf("</hosts>\n");
		printf("<services>\n");

	} else if (content_type == CSV_CONTENT) {
		printf("%s服务组%s服务状态细分%s%s\n", csv_data_enclosure, sg->group_name, csv_data_enclosure, csv_delimiter);

		for (i = 0; i < (sheader_num - 5); i++)
			printf("%s%s%s%s", csv_data_enclosure, sheader[i], csv_data_enclosure, csv_delimiter);

		printf("\n");
	}

	current_subject = 0;
	average_percent_time_indeterminate = 0.0;

	for (temp_subject = subject_list; temp_subject != NULL; temp_subject = temp_subject->next) {

		if (temp_subject->type != SERVICE_SUBJECT)
			continue;

		temp_service = find_service(temp_subject->host_name, temp_subject->service_description);
		if (temp_service == NULL)
			continue;

		if (is_service_member_of_servicegroup(sg, temp_service) == FALSE)
			continue;

		current_subject++;

		time_determinate = temp_subject->time_ok + temp_subject->time_warning + temp_subject->time_unknown + temp_subject->time_critical;
		time_indeterminate = total_time - time_determinate;

		/* adjust indeterminate time due to insufficient data (not all was caught) */
		temp_subject->time_indeterminate_nodata = time_indeterminate - temp_subject->time_indeterminate_notrunning;

		/* initialize values */
		percent_time_ok = 0.0;
		percent_time_warning = 0.0;
		percent_time_unknown = 0.0;
		percent_time_critical = 0.0;
		percent_time_indeterminate = 0.0;
		percent_time_ok_known = 0.0;
		percent_time_warning_known = 0.0;
		percent_time_unknown_known = 0.0;
		percent_time_critical_known = 0.0;

		if (total_time > 0) {
			percent_time_ok = (double)(((double)temp_subject->time_ok * 100.0) / (double)total_time);
			percent_time_warning = (double)(((double)temp_subject->time_warning * 100.0) / (double)total_time);
			percent_time_unknown = (double)(((double)temp_subject->time_unknown * 100.0) / (double)total_time);
			percent_time_critical = (double)(((double)temp_subject->time_critical * 100.0) / (double)total_time);
			percent_time_indeterminate = (double)(((double)time_indeterminate * 100.0) / (double)total_time);
			if (time_determinate > 0) {
				percent_time_ok_known = (double)(((double)temp_subject->time_ok * 100.0) / (double)time_determinate);
				percent_time_warning_known = (double)(((double)temp_subject->time_warning * 100.0) / (double)time_determinate);
				percent_time_unknown_known = (double)(((double)temp_subject->time_unknown * 100.0) / (double)time_determinate);
				percent_time_critical_known = (double)(((double)temp_subject->time_critical * 100.0) / (double)time_determinate);
			}
		}

		if (odd) {
			odd = 0;
			bgclass = "Odd";
		} else {
			odd = 1;
			bgclass = "Even";
		}

		if (content_type == HTML_CONTENT) {

			printf("<tr CLASS='data%s'><td CLASS='data%s'>", bgclass, bgclass);
			if (strcmp(temp_subject->host_name, last_host))
				host_report_url(temp_subject->host_name, temp_subject->host_name);
			printf("</td><td CLASS='data%s'>", bgclass);
			service_report_url(temp_subject->host_name, temp_subject->service_description, (temp_service->display_name != NULL) ? temp_service->display_name : temp_service->description);
			printf("</td><td CLASS='serviceOK'>%2.3f%% (%2.3f%%)</td><td CLASS='serviceWARNING'>%2.3f%% (%2.3f%%)</td><td CLASS='serviceUNKNOWN'>%2.3f%% (%2.3f%%)</td><td class='serviceCRITICAL'>%2.3f%% (%2.3f%%)</td><td class='data%s' align='center'>%2.3f%%</td></tr>\n", percent_time_ok, percent_time_ok_known, percent_time_warning, percent_time_warning_known, percent_time_unknown, percent_time_unknown_known, percent_time_critical, percent_time_critical_known, bgclass, percent_time_indeterminate);

			strncpy(last_host, temp_subject->host_name, sizeof(last_host) - 1);
			last_host[sizeof(last_host)-1] = '\x0';

		} else if (content_type == JSON_CONTENT) {
			if (json_start != TRUE)
				printf(",\n");

			temp_host = find_host(temp_subject->host_name);

			/* host name and service description */
			printf("{ \"%s\": \"%s\", ", sheader[0], json_encode(temp_subject->host_name));
			printf(" \"%s\": \"%s\", ", sheader[47], (temp_host != NULL && temp_host->display_name != NULL) ? json_encode(temp_host->display_name) : json_encode(temp_host->name));
			printf(" \"%s\": \"%s\", ", sheader[1], json_encode(temp_subject->service_description));
			printf(" \"%s\": \"%s\", ", sheader[48], (temp_service->display_name != NULL) ? json_encode(temp_service->display_name) : json_encode(temp_service->description));

			/* ok times */
			printf(" \"%s\": %lu, ", sheader[2], temp_subject->scheduled_time_ok);
			printf(" \"%s\": %2.3f, ", sheader[3], percent_time_ok_scheduled);
			printf(" \"%s\": %2.3f, ", sheader[4], percent_time_ok_scheduled_known);
			printf(" \"%s\": %lu, ", sheader[5], temp_subject->time_ok - temp_subject->scheduled_time_ok);
			printf(" \"%s\": %2.3f, ", sheader[6], percent_time_ok_unscheduled);
			printf(" \"%s\": %2.3f, ", sheader[7], percent_time_ok_unscheduled_known);
			printf(" \"%s\": %lu, ", sheader[8], temp_subject->time_ok);
			printf(" \"%s\": %2.3f, ", sheader[9], percent_time_ok);
			printf(" \"%s\": %2.3f, ", sheader[10], percent_time_ok_known);

			/* warning times */
			printf(" \"%s\": %lu, ", sheader[11], temp_subject->scheduled_time_warning);
			printf(" \"%s\": %2.3f, ", sheader[12], percent_time_warning_scheduled);
			printf(" \"%s\": %2.3f, ", sheader[13], percent_time_warning_scheduled_known);
			printf(" \"%s\": %lu, ", sheader[14], temp_subject->time_warning - temp_subject->scheduled_time_warning);
			printf(" \"%s\": %2.3f, ", sheader[15], percent_time_warning_unscheduled);
			printf(" \"%s\": %2.3f, ", sheader[16], percent_time_warning_unscheduled_known);
			printf(" \"%s\": %lu, ", sheader[17], temp_subject->time_warning);
			printf(" \"%s\": %2.3f, ", sheader[18], percent_time_warning);
			printf(" \"%s\": %2.3f, ", sheader[19], percent_time_warning_known);

			/* unknown times */
			printf(" \"%s\": %lu, ", sheader[20], temp_subject->scheduled_time_unknown);
			printf(" \"%s\": %2.3f, ", sheader[21], percent_time_unknown_scheduled);
			printf(" \"%s\": %2.3f, ", sheader[22], percent_time_unknown_scheduled_known);
			printf(" \"%s\": %lu, ", sheader[23], temp_subject->time_unknown - temp_subject->scheduled_time_unknown);
			printf(" \"%s\": %2.3f, ", sheader[24], percent_time_unknown_unscheduled);
			printf(" \"%s\": %2.3f, ", sheader[25], percent_time_unknown_unscheduled_known);
			printf(" \"%s\": %lu, ", sheader[26], temp_subject->time_unknown);
			printf(" \"%s\": %2.3f, ", sheader[27], percent_time_unknown);
			printf(" \"%s\": %2.3f, ", sheader[28], percent_time_unknown_known);

			/* critical times */
			printf(" \"%s\": %lu, ", sheader[29], temp_subject->scheduled_time_critical);
			printf(" \"%s\": %2.3f, ", sheader[30], percent_time_critical_scheduled);
			printf(" \"%s\": %2.3f, ", sheader[31], percent_time_critical_scheduled_known);
			printf(" \"%s\": %lu, ", sheader[32], temp_subject->time_critical - temp_subject->scheduled_time_critical);
			printf(" \"%s\": %2.3f, ", sheader[33], percent_time_critical_unscheduled);
			printf(" \"%s\": %2.3f, ", sheader[34], percent_time_critical_unscheduled_known);
			printf(" \"%s\": %lu, ", sheader[35], temp_subject->time_critical);
			printf(" \"%s\": %2.3f, ", sheader[36], percent_time_critical);
			printf(" \"%s\": %2.3f, ", sheader[37], percent_time_critical_known);


			/* indeterminate times */
			printf(" \"%s\": %lu, ", sheader[38], temp_subject->time_indeterminate_notrunning);
			printf(" \"%s\": %2.3f, ", sheader[39], percent_time_indeterminate_notrunning);
			printf(" \"%s\": %lu, ", sheader[40], temp_subject->time_indeterminate_nodata);
			printf(" \"%s\": %2.3f, ", sheader[41], percent_time_indeterminate_nodata);
			printf(" \"%s\": %lu, ", sheader[42], time_indeterminate);
			printf(" \"%s\": %2.3f} ", sheader[43], percent_time_indeterminate);

			json_start = FALSE;

		} else if (content_type == XML_CONTENT) {

			printf("<service name=\"%s\" host_name=\"%s\">\n", temp_subject->service_description, temp_subject->host_name);

			/* ok times */
			printf("<%s>%lu</%s>\n", sheader[2], temp_subject->scheduled_time_ok, sheader[2]);
			printf("<%s>%2.3f</%s>\n", sheader[3], percent_time_ok_scheduled, sheader[3]);
			printf("<%s>%2.3f</%s>\n", sheader[4], percent_time_ok_scheduled_known, sheader[4]);
			printf("<%s>%lu</%s>\n", sheader[5], temp_subject->time_ok - temp_subject->scheduled_time_ok, sheader[5]);
			printf("<%s>%2.3f</%s>\n", sheader[6], percent_time_ok_unscheduled, sheader[6]);
			printf("<%s>%2.3f</%s>\n", sheader[7], percent_time_ok_unscheduled_known, sheader[7]);
			printf("<%s>%lu</%s>\n", sheader[8], temp_subject->time_ok, sheader[8]);
			printf("<%s>%2.3f</%s>\n", sheader[9], percent_time_ok, sheader[9]);
			printf("<%s>%2.3f</%s>\n", sheader[10], percent_time_ok_known, sheader[10]);

			/* warning times */
			printf("<%s>%lu</%s>\n", sheader[11], temp_subject->scheduled_time_warning, sheader[11]);
			printf("<%s>%2.3f</%s>\n", sheader[12], percent_time_warning_scheduled, sheader[12]);
			printf("<%s>%2.3f</%s>\n", sheader[13], percent_time_warning_scheduled_known, sheader[13]);
			printf("<%s>%lu</%s>\n", sheader[14], temp_subject->time_warning - temp_subject->scheduled_time_warning, sheader[14]);
			printf("<%s>%2.3f</%s>\n", sheader[15], percent_time_warning_unscheduled, sheader[15]);
			printf("<%s>%2.3f</%s>\n", sheader[16], percent_time_warning_unscheduled_known, sheader[16]);
			printf("<%s>%lu</%s>\n", sheader[17], temp_subject->time_warning, sheader[17]);
			printf("<%s>%2.3f</%s>\n", sheader[18], percent_time_warning, sheader[18]);
			printf("<%s>%2.3f</%s>\n", sheader[19], percent_time_warning_known, sheader[19]);

			/* unknown times */
			printf("<%s>%lu</%s>\n", sheader[20], temp_subject->scheduled_time_unknown, sheader[20]);
			printf("<%s>%2.3f</%s>\n", sheader[21], percent_time_unknown_scheduled, sheader[21]);
			printf("<%s>%2.3f</%s>\n", sheader[22], percent_time_unknown_scheduled_known, sheader[22]);
			printf("<%s>%lu</%s>\n", sheader[23], temp_subject->time_unknown - temp_subject->scheduled_time_unknown, sheader[23]);
			printf("<%s>%2.3f</%s>\n", sheader[24], percent_time_unknown_unscheduled, sheader[24]);
			printf("<%s>%2.3f</%s>\n", sheader[25], percent_time_unknown_unscheduled_known, sheader[25]);
			printf("<%s>%lu</%s>\n", sheader[26], temp_subject->time_unknown, sheader[26]);
			printf("<%s>%2.3f</%s>\n", sheader[27], percent_time_unknown, sheader[27]);
			printf("<%s>%2.3f</%s>\n", sheader[28], percent_time_unknown_known, sheader[28]);

			/* critical times */
			printf("<%s>%lu</%s>\n", sheader[29], temp_subject->scheduled_time_critical, sheader[29]);
			printf("<%s>%2.3f</%s>\n", sheader[30], percent_time_critical_scheduled, sheader[30]);
			printf("<%s>%2.3f</%s>\n", sheader[31], percent_time_critical_scheduled_known, sheader[31]);
			printf("<%s>%lu</%s>\n", sheader[32], temp_subject->time_critical - temp_subject->scheduled_time_critical, sheader[32]);
			printf("<%s>%2.3f</%s>\n", sheader[33], percent_time_critical_unscheduled, sheader[33]);
			printf("<%s>%2.3f</%s>\n", sheader[34], percent_time_critical_unscheduled_known, sheader[34]);
			printf("<%s>%lu</%s>\n", sheader[35], temp_subject->time_critical, sheader[35]);
			printf("<%s>%2.3f</%s>\n", sheader[36], percent_time_critical, sheader[36]);
			printf("<%s>%2.3f</%s>\n", sheader[37], percent_time_critical_known, sheader[37]);


			/* indeterminate times */
			printf("<%s>%lu</%s>\n", sheader[38], temp_subject->time_indeterminate_notrunning, sheader[38]);
			printf("<%s>%2.3f</%s>\n", sheader[39], percent_time_indeterminate_notrunning, sheader[39]);
			printf("<%s>%lu</%s>\n", sheader[40], temp_subject->time_indeterminate_nodata, sheader[40]);
			printf("<%s>%2.3f</%s>\n", sheader[41], percent_time_indeterminate_nodata, sheader[41]);
			printf("<%s>%lu</%s>\n", sheader[42], time_indeterminate, sheader[42]);
			printf("<%s>%2.3f</%s>\n", sheader[43], percent_time_indeterminate, sheader[43]);

			printf("</service>\n");

		} else if (content_type == CSV_CONTENT) {

			/* host name and service description */
			printf("%s%s%s%s", csv_data_enclosure, temp_subject->host_name, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, temp_subject->service_description, csv_data_enclosure, csv_delimiter);

			/* ok times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_ok, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok_scheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok_scheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_ok - temp_subject->scheduled_time_ok, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok_unscheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok_unscheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_ok, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok_known, csv_data_enclosure, csv_delimiter);

			/* warning times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_warning, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning_scheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning_scheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_warning - temp_subject->scheduled_time_warning, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning_unscheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning_unscheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_warning, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning_known, csv_data_enclosure, csv_delimiter);

			/* unknown times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_unknown, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown_scheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown_scheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_unknown - temp_subject->scheduled_time_unknown, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown_unscheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown_unscheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_unknown, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown_known, csv_data_enclosure, csv_delimiter);

			/* critical times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_critical, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical_scheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical_scheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_critical - temp_subject->scheduled_time_critical, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical_unscheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical_unscheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_critical, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical_known, csv_data_enclosure, csv_delimiter);

			/* indeterminate times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_indeterminate_notrunning, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate_notrunning, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_indeterminate_nodata, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate_nodata, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, time_indeterminate, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate, csv_data_enclosure, csv_delimiter);

			printf("\n");
		}

		get_running_average(&average_percent_time_ok, percent_time_ok, current_subject);
		get_running_average(&average_percent_time_ok_known, percent_time_ok_known, current_subject);
		get_running_average(&average_percent_time_unknown, percent_time_unknown, current_subject);
		get_running_average(&average_percent_time_unknown_known, percent_time_unknown_known, current_subject);
		get_running_average(&average_percent_time_warning, percent_time_warning, current_subject);
		get_running_average(&average_percent_time_warning_known, percent_time_warning_known, current_subject);
		get_running_average(&average_percent_time_critical, percent_time_critical, current_subject);
		get_running_average(&average_percent_time_critical_known, percent_time_critical_known, current_subject);
		get_running_average(&average_percent_time_indeterminate, percent_time_indeterminate, current_subject);
	}

	/* display average stats */
	if (odd) {
		odd = 0;
		bgclass = "Odd";
	} else {
		odd = 1;
		bgclass = "Even";
	}

	if (content_type == HTML_CONTENT) {
		printf("<tr CLASS='data%s'><td CLASS='data%s' colspan='2'>平均</td><td CLASS='serviceOK'>%2.3f%% (%2.3f%%)</td><td CLASS='serviceWARNING'>%2.3f%% (%2.3f%%)</td><td CLASS='serviceUNKNOWN'>%2.3f%% (%2.3f%%)</td><td class='serviceCRITICAL'>%2.3f%% (%2.3f%%)</td><td class='data%s' align='center'>%2.3f%%</td></tr>\n", bgclass, bgclass, average_percent_time_ok, average_percent_time_ok_known, average_percent_time_warning, average_percent_time_warning_known, average_percent_time_unknown, average_percent_time_unknown_known, average_percent_time_critical, average_percent_time_critical_known, bgclass, average_percent_time_indeterminate);
		printf("</table>\n");
	} else if (content_type == JSON_CONTENT) {
		printf(" ],\n");
		printf("\"所有服务的平均值\": [ {");
		printf("\"正常时间平均百分比\": %2.3f, ", average_percent_time_ok);
		printf("\"已知正常时间平均百分比\": %2.3f, ", average_percent_time_ok_known);
		printf("\"警报时间平均百分比\": %2.3f, ", average_percent_time_warning);
		printf("\"已知警报时间平均百分比\": %2.3f, ", average_percent_time_warning_known);
		printf("\"未知时间平均百分比\": %2.3f, ", average_percent_time_unknown);
		printf("\"已知未知时间平均百分比\": %2.3f, ", average_percent_time_unknown_known);
		printf("\"严重时间平均百分比\": %2.3f, ", average_percent_time_critical);
		printf("\"已知严重时间平均百分比\": %2.3f, ", average_percent_time_critical_known);
		printf("\"未决时间平均百分比\": %2.3f } ] }\n", average_percent_time_indeterminate);
	} else if (content_type == XML_CONTENT) {
		printf("<all_services_average>\n");
		printf("<average_percent_time_ok>%2.3f</average_percent_time_ok>\n", average_percent_time_ok);
		printf("<average_percent_time_ok_known>%2.3f</average_percent_time_ok_known>\n", average_percent_time_ok_known);
		printf("<average_percent_time_warning>%2.3f</average_percent_time_warning>\n", average_percent_time_warning);
		printf("<average_percent_time_warning_known>%2.3f</average_percent_time_warning_known>\n", average_percent_time_warning_known);
		printf("<average_percent_time_unknown>%2.3f</average_percent_time_unknown>\n", average_percent_time_unknown);
		printf("<average_percent_time_unknown_known>%2.3f</average_percent_time_unknown_known>\n", average_percent_time_unknown_known);
		printf("<average_percent_time_critical>%2.3f</average_percent_time_critical>\n", average_percent_time_critical);
		printf("<average_percent_time_critical_known>%2.3f</average_percent_time_critical_known>\n", average_percent_time_critical_known);
		printf("<average_percent_time_indeterminate>%2.3f</average_percent_time_indeterminate>\n", average_percent_time_indeterminate);
		printf("</all_services_average>\n");
		printf("</services>\n");
		printf("</servicegroup>\n");
	} else if (content_type == CSV_CONTENT) {
		/* average */
		/* left for future rework */
	}

	return;
}


/* display host availability */
void display_host_availability(void) {
	unsigned long total_time;
	unsigned long time_determinate;
	unsigned long time_indeterminate;
	avail_subject *temp_subject;
	host *temp_host;
	service *temp_service;
	int days, hours, minutes, seconds;
	char time_indeterminate_string[48];
	char time_determinate_string[48];
	char total_time_string[48];
	double percent_time_ok = 0.0;
	double percent_time_warning = 0.0;
	double percent_time_unknown = 0.0;
	double percent_time_critical = 0.0;
	double percent_time_indeterminate = 0.0;
	double percent_time_ok_known = 0.0;
	double percent_time_warning_known = 0.0;
	double percent_time_unknown_known = 0.0;
	double percent_time_critical_known = 0.0;
	char time_up_string[48];
	char time_down_string[48];
	char time_unreachable_string[48];
	double percent_time_up = 0.0;
	double percent_time_down = 0.0;
	double percent_time_unreachable = 0.0;
	double percent_time_up_known = 0.0;
	double percent_time_down_known = 0.0;
	double percent_time_unreachable_known = 0.0;

	double percent_time_up_scheduled = 0.0;
	double percent_time_up_unscheduled = 0.0;
	double percent_time_down_scheduled = 0.0;
	double percent_time_down_unscheduled = 0.0;
	double percent_time_unreachable_scheduled = 0.0;
	double percent_time_unreachable_unscheduled = 0.0;
	double percent_time_up_scheduled_known = 0.0;
	double percent_time_up_unscheduled_known = 0.0;
	double percent_time_down_scheduled_known = 0.0;
	double percent_time_down_unscheduled_known = 0.0;
	double percent_time_unreachable_scheduled_known = 0.0;
	double percent_time_unreachable_unscheduled_known = 0.0;
	char time_up_scheduled_string[48];
	char time_up_unscheduled_string[48];
	char time_down_scheduled_string[48];
	char time_down_unscheduled_string[48];
	char time_unreachable_scheduled_string[48];
	char time_unreachable_unscheduled_string[48];

	char time_indeterminate_scheduled_string[48];
	char time_indeterminate_unscheduled_string[48];
	double percent_time_indeterminate_scheduled = 0.0;
	double percent_time_indeterminate_unscheduled = 0.0;
	char time_indeterminate_notrunning_string[48];
	char time_indeterminate_nodata_string[48];
	double percent_time_indeterminate_notrunning = 0.0;
	double percent_time_indeterminate_nodata = 0.0;

	double average_percent_time_up = 0.0;
	double average_percent_time_up_known = 0.0;
	double average_percent_time_down = 0.0;
	double average_percent_time_down_known = 0.0;
	double average_percent_time_unreachable = 0.0;
	double average_percent_time_unreachable_known = 0.0;
	double average_percent_time_indeterminate = 0.0;

	double average_percent_time_ok = 0.0;
	double average_percent_time_ok_known = 0.0;
	double average_percent_time_unknown = 0.0;
	double average_percent_time_unknown_known = 0.0;
	double average_percent_time_warning = 0.0;
	double average_percent_time_warning_known = 0.0;
	double average_percent_time_critical = 0.0;
	double average_percent_time_critical_known = 0.0;

	int current_subject = 0;
	int i = 0;
	char *bgclass = "";
	int odd = 1;
	int json_start = TRUE;


	/* calculate total time during period based on timeperiod used for reporting */
	total_time = calculate_total_time(t1, t2);

#ifdef DEBUG
	printf("总计时间: '%ld'秒<br>\n", total_time);
#endif

	/* show data for a specific host */
	if (show_all_hosts == FALSE) {

		temp_subject = find_subject(HOST_SUBJECT, host_name, NULL);
		if (temp_subject == NULL)
			return;

		temp_host = find_host(temp_subject->host_name);
		if (temp_host == NULL)
			return;

		/* the user isn't authorized to view this host */
		if (is_authorized_for_host(temp_host, &current_authdata) == FALSE)
			return;

		time_determinate = temp_subject->time_up + temp_subject->time_down + temp_subject->time_unreachable;
		time_indeterminate = total_time - time_determinate;

		/* adjust indeterminate time due to insufficient data (not all was caught) */
		temp_subject->time_indeterminate_nodata = time_indeterminate - temp_subject->time_indeterminate_notrunning;

		/* up times */
		get_time_breakdown(temp_subject->time_up, &days, &hours, &minutes, &seconds);
		snprintf(time_up_string, sizeof(time_up_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->scheduled_time_up, &days, &hours, &minutes, &seconds);
		snprintf(time_up_scheduled_string, sizeof(time_up_scheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->time_up - temp_subject->scheduled_time_up, &days, &hours, &minutes, &seconds);
		snprintf(time_up_unscheduled_string, sizeof(time_up_unscheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);

		/* down times */
		get_time_breakdown(temp_subject->time_down, &days, &hours, &minutes, &seconds);
		snprintf(time_down_string, sizeof(time_down_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->scheduled_time_down, &days, &hours, &minutes, &seconds);
		snprintf(time_down_scheduled_string, sizeof(time_down_scheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->time_down - temp_subject->scheduled_time_down, &days, &hours, &minutes, &seconds);
		snprintf(time_down_unscheduled_string, sizeof(time_down_unscheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);

		/* unreachable times */
		get_time_breakdown(temp_subject->time_unreachable, &days, &hours, &minutes, &seconds);
		snprintf(time_unreachable_string, sizeof(time_unreachable_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->scheduled_time_unreachable, &days, &hours, &minutes, &seconds);
		snprintf(time_unreachable_scheduled_string, sizeof(time_unreachable_scheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->time_unreachable - temp_subject->scheduled_time_unreachable, &days, &hours, &minutes, &seconds);
		snprintf(time_unreachable_unscheduled_string, sizeof(time_unreachable_unscheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);

		/* indeterminate times */
		get_time_breakdown(time_indeterminate, &days, &hours, &minutes, &seconds);
		snprintf(time_indeterminate_string, sizeof(time_indeterminate_string) - 1, "%02d天%02d時%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->scheduled_time_indeterminate, &days, &hours, &minutes, &seconds);
		snprintf(time_indeterminate_scheduled_string, sizeof(time_indeterminate_scheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(time_indeterminate - temp_subject->scheduled_time_indeterminate, &days, &hours, &minutes, &seconds);
		snprintf(time_indeterminate_unscheduled_string, sizeof(time_indeterminate_unscheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->time_indeterminate_notrunning, &days, &hours, &minutes, &seconds);
		snprintf(time_indeterminate_notrunning_string, sizeof(time_indeterminate_notrunning_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->time_indeterminate_nodata, &days, &hours, &minutes, &seconds);
		snprintf(time_indeterminate_nodata_string, sizeof(time_indeterminate_nodata_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);

		get_time_breakdown(time_determinate, &days, &hours, &minutes, &seconds);
		snprintf(time_determinate_string, sizeof(time_determinate_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);

		get_time_breakdown(total_time, &days, &hours, &minutes, &seconds);
		snprintf(total_time_string, sizeof(total_time_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);

		if (total_time > 0) {
			percent_time_up = (double)(((double)temp_subject->time_up * 100.0) / (double)total_time);
			percent_time_up_scheduled = (double)(((double)temp_subject->scheduled_time_up * 100.0) / (double)total_time);
			percent_time_up_unscheduled = percent_time_up - percent_time_up_scheduled;
			percent_time_down = (double)(((double)temp_subject->time_down * 100.0) / (double)total_time);
			percent_time_down_scheduled = (double)(((double)temp_subject->scheduled_time_down * 100.0) / (double)total_time);
			percent_time_down_unscheduled = percent_time_down - percent_time_down_scheduled;
			percent_time_unreachable = (double)(((double)temp_subject->time_unreachable * 100.0) / (double)total_time);
			percent_time_unreachable_scheduled = (double)(((double)temp_subject->scheduled_time_unreachable * 100.0) / (double)total_time);
			percent_time_unreachable_unscheduled = percent_time_unreachable - percent_time_unreachable_scheduled;
			percent_time_indeterminate = (double)(((double)time_indeterminate * 100.0) / (double)total_time);
			percent_time_indeterminate_scheduled = (double)(((double)temp_subject->scheduled_time_indeterminate * 100.0) / (double)total_time);
			percent_time_indeterminate_unscheduled = percent_time_indeterminate - percent_time_indeterminate_scheduled;
			percent_time_indeterminate_notrunning = (double)(((double)temp_subject->time_indeterminate_notrunning * 100.0) / (double)total_time);
			percent_time_indeterminate_nodata = (double)(((double)temp_subject->time_indeterminate_nodata * 100.0) / (double)total_time);
			if (time_determinate > 0) {
				percent_time_up_known = (double)(((double)temp_subject->time_up * 100.0) / (double)time_determinate);
				percent_time_up_scheduled_known = (double)(((double)temp_subject->scheduled_time_up * 100.0) / (double)time_determinate);
				percent_time_up_unscheduled_known = percent_time_up_known - percent_time_up_scheduled_known;
				percent_time_down_known = (double)(((double)temp_subject->time_down * 100.0) / (double)time_determinate);
				percent_time_down_scheduled_known = (double)(((double)temp_subject->scheduled_time_down * 100.0) / (double)time_determinate);
				percent_time_down_unscheduled_known = percent_time_down_known - percent_time_down_scheduled_known;
				percent_time_unreachable_known = (double)(((double)temp_subject->time_unreachable * 100.0) / (double)time_determinate);
				percent_time_unreachable_scheduled_known = (double)(((double)temp_subject->scheduled_time_unreachable * 100.0) / (double)time_determinate);
				percent_time_unreachable_unscheduled_known = percent_time_unreachable_known - percent_time_unreachable_scheduled_known;
			}
		}

		if (content_type == HTML_CONTENT || content_type == JSON_CONTENT || content_type == XML_CONTENT) {

			if (content_type == HTML_CONTENT) {
				printf("<DIV ALIGN=CENTER CLASS='dataTitle'>主机状态细分:</DIV>\n");

#ifdef USE_TRENDS
				printf("<p align='center'>\n");
				printf("<a href='%s?host=%s", TRENDS_CGI, url_encode(host_name));
				printf("&t1=%lu&t2=%lu&includesoftstates=%s&assumestateretention=%s&assumeinitialstates=%s&assumestatesduringnotrunning=%s&initialassumedhoststate=%d&backtrack=%d'>", t1, t2, (include_soft_states == TRUE) ? "yes" : "no", (assume_state_retention == TRUE) ? "yes" : "no", (assume_initial_states == TRUE) ? "yes" : "no", (assume_states_during_notrunning == TRUE) ? "yes" : "no", initial_assumed_host_state, backtrack_archives);
				printf("<img src='%s?createimage&smallimage&host=%s", TRENDS_CGI, url_encode(host_name));
				printf("&t1=%lu&t2=%lu&includesoftstates=%s&assumestateretention=%s&assumeinitialstates=%s&assumestatesduringnotrunning=%s&initialassumedhoststate=%d&backtrack=%d' border=1 alt='主机状态趋势' title='主机状态趋势' width='500' height='20'>", t1, t2, (include_soft_states == TRUE) ? "yes" : "no", (assume_state_retention == TRUE) ? "yes" : "no", (assume_initial_states == TRUE) ? "yes" : "no", (assume_states_during_notrunning == TRUE) ? "yes" : "no", initial_assumed_host_state, backtrack_archives);
				printf("</a><br>\n");
				printf("</p>\n");
#endif
				printf("<TABLE BORDER=0 CLASS='data' align='center'>\n");
				printf("<TR><TH CLASS='data'>状态</TH><TH CLASS='data'>类型/原因</TH><TH CLASS='data'>时间</TH><TH CLASS='data'>%% 总计时间</TH><TH CLASS='data'>%% 已知时间</TH></TR>\n");

				/* up times */
				printf("<tr CLASS='dataEven'><td CLASS='hostUP' rowspan=3>运行</td>");
				printf("<td CLASS='dataEven'>未安排</td><td CLASS='dataEven'>%s</td><td CLASS='dataEven'>%2.3f%%</td><td class='dataEven'>%2.3f%%</td></tr>\n", time_up_unscheduled_string, percent_time_up, percent_time_up_known);
				printf("<tr CLASS='dataEven'><td CLASS='dataEven'>安排</td><td CLASS='dataEven'>%s</td><td CLASS='dataEven'>%2.3f%%</td><td class='dataEven'>%2.3f%%</td></tr>\n", time_up_scheduled_string, percent_time_up_scheduled, percent_time_up_scheduled_known);
				printf("<tr CLASS='hostUP'><td CLASS='hostUP'>总计</td><td CLASS='hostUP'>%s</td><td CLASS='hostUP'>%2.3f%%</td><td class='hostUP'>%2.3f%%</td></tr>\n", time_up_string, percent_time_up, percent_time_up_known);

				/* down times */
				printf("<tr CLASS='dataOdd'><td CLASS='hostDOWN' rowspan=3>宕机</td>");
				printf("<td CLASS='dataOdd'>未安排</td><td CLASS='dataOdd'>%s</td><td CLASS='dataOdd'>%2.3f%%</td><td class='dataOdd'>%2.3f%%</td></tr>\n", time_down_unscheduled_string, percent_time_down_unscheduled, percent_time_down_unscheduled_known);
				printf("<tr CLASS='dataOdd'><td CLASS='dataOdd'>安排</td><td CLASS='dataOdd'>%s</td><td CLASS='dataOdd'>%2.3f%%</td><td class='dataOdd'>%2.3f%%</td></tr>\n", time_down_scheduled_string, percent_time_down_scheduled, percent_time_down_scheduled_known);
				printf("<tr CLASS='hostDOWN'><td CLASS='hostDOWN'>总计</td><td CLASS='hostDOWN'>%s</td><td CLASS='hostDOWN'>%2.3f%%</td><td class='hostDOWN'>%2.3f%%</td></tr>\n", time_down_string, percent_time_down, percent_time_down_known);

				/* unreachable times */
				printf("<tr CLASS='dataEven'><td CLASS='hostUNREACHABLE' rowspan=3>无法访问</td>");
				printf("<td CLASS='dataEven'>未安排</td><td CLASS='dataEven'>%s</td><td CLASS='dataEven'>%2.3f%%</td><td class='dataEven'>%2.3f%%</td></tr>\n", time_unreachable_unscheduled_string, percent_time_unreachable, percent_time_unreachable_known);
				printf("<tr CLASS='dataEven'><td CLASS='dataEven'>安排</td><td CLASS='dataEven'>%s</td><td CLASS='dataEven'>%2.3f%%</td><td class='dataEven'>%2.3f%%</td></tr>\n", time_unreachable_scheduled_string, percent_time_unreachable_scheduled, percent_time_unreachable_scheduled_known);
				printf("<tr CLASS='hostUNREACHABLE'><td CLASS='hostUNREACHABLE'>总计</td><td CLASS='hostUNREACHABLE'>%s</td><td CLASS='hostUNREACHABLE'>%2.3f%%</td><td class='hostUNREACHABLE'>%2.3f%%</td></tr>\n", time_unreachable_string, percent_time_unreachable, percent_time_unreachable_known);

				/* indeterminate times */
				printf("<tr CLASS='dataOdd'><td CLASS='dataOdd' rowspan=3>未决</td>");
				printf("<td CLASS='dataOdd'>%s 未运行</td><td CLASS='dataOdd'>%s</td><td CLASS='dataOdd'>%2.3f%%</td><td CLASS='dataOdd'></td></tr>\n", PROGRAM_VERSION, time_indeterminate_notrunning_string, percent_time_indeterminate_notrunning);
				printf("<tr CLASS='dataOdd'><td CLASS='dataOdd'>数据不足</td><td CLASS='dataOdd'>%s</td><td CLASS='dataOdd'>%2.3f%%</td><td CLASS='dataOdd'></td></tr>\n", time_indeterminate_nodata_string, percent_time_indeterminate_nodata);
				printf("<tr CLASS='dataOdd'><td CLASS='dataOdd'>总计</td><td CLASS='dataOdd'>%s</td><td CLASS='dataOdd'>%2.3f%%</td><td CLASS='dataOdd'></td></tr>\n", time_indeterminate_string, percent_time_indeterminate);

				printf("<tr><td colspan=3></td></tr>\n");

				printf("<tr CLASS='dataEven'><td CLASS='dataEven'>所有</td><td class='dataEven'>总计</td><td CLASS='dataEven'>%s</td><td CLASS='dataEven'>100.000%%</td><td CLASS='dataEven'>100.000%%</td></tr>\n", total_time_string);
				printf("</table>\n");


				/* display state breakdowns for all services on this host */

				printf("<BR><BR>\n");
				printf("<DIV ALIGN=CENTER CLASS='dataTitle'>主机服务状态细分:</DIV>\n");

				printf("<TABLE BORDER=0 CLASS='data' align='center'>\n");
				printf("<TR><TH CLASS='data'>服务</TH><TH CLASS='data'>%% 正常时间</TH><TH CLASS='data'>%% 警报时间</TH><TH CLASS='data'>%% 未知时间</TH><TH CLASS='data'>%% 严重时间</TH><TH CLASS='data'>%% 未决时间</TH></TR>\n");

			} else if (content_type == JSON_CONTENT) {

				printf("\"主机可用性\": {\n");
				printf("\"主机\": [\n");

				/* host name */
				printf("{ \"%s\": \"%s\", ", hheader[0], json_encode(temp_subject->host_name));
				printf("{ \"%s\": \"%s\", ", hheader[37], (temp_host->display_name != NULL) ? json_encode(temp_host->display_name) : json_encode(temp_host->name));

				/* up times */
				printf(" \"%s\": %lu, ", hheader[1], temp_subject->scheduled_time_up);
				printf(" \"%s\": %2.3f, ", hheader[2], percent_time_up_scheduled);
				printf(" \"%s\": %2.3f, ", hheader[3], percent_time_up_scheduled_known);
				printf(" \"%s\": %lu, ", hheader[4], temp_subject->time_up - temp_subject->scheduled_time_up);
				printf(" \"%s\": %2.3f, ", hheader[5], percent_time_up_unscheduled);
				printf(" \"%s\": %2.3f, ", hheader[6], percent_time_up_unscheduled_known);
				printf(" \"%s\": %lu, ", hheader[7], temp_subject->time_up);
				printf(" \"%s\": %2.3f, ", hheader[8], percent_time_up);
				printf(" \"%s\": %2.3f, ", hheader[9], percent_time_up_known);

				/* down times */
				printf(" \"%s\": %lu, ", hheader[10], temp_subject->scheduled_time_down);
				printf(" \"%s\": %2.3f, ", hheader[11], percent_time_down_scheduled);
				printf(" \"%s\": %2.3f, ", hheader[12], percent_time_down_scheduled_known);
				printf(" \"%s\": %lu, ", hheader[13], temp_subject->time_down - temp_subject->scheduled_time_down);
				printf(" \"%s\": %2.3f, ", hheader[14], percent_time_down_unscheduled);
				printf(" \"%s\": %2.3f, ", hheader[15], percent_time_down_unscheduled_known);
				printf(" \"%s\": %lu, ", hheader[16], temp_subject->time_down);
				printf(" \"%s\": %2.3f, ", hheader[17], percent_time_down);
				printf(" \"%s\": %2.3f, ", hheader[18], percent_time_down_known);

				/* unreachable times */
				printf(" \"%s\": %lu, ", hheader[19], temp_subject->scheduled_time_unreachable);
				printf(" \"%s\": %2.3f, ", hheader[20], percent_time_unreachable_scheduled);
				printf(" \"%s\": %2.3f, ", hheader[21], percent_time_unreachable_scheduled_known);
				printf(" \"%s\": %lu, ", hheader[22], temp_subject->time_unreachable - temp_subject->scheduled_time_unreachable);
				printf(" \"%s\": %2.3f, ", hheader[23], percent_time_unreachable_unscheduled);
				printf(" \"%s\": %2.3f, ", hheader[24], percent_time_unreachable_unscheduled_known);
				printf(" \"%s\": %lu, ", hheader[25], temp_subject->time_unreachable);
				printf(" \"%s\": %2.3f, ", hheader[26], percent_time_unreachable);
				printf(" \"%s\": %2.3f, ", hheader[27], percent_time_unreachable_known);

				/* indeterminate times */
				printf(" \"%s\": %lu, ", hheader[28], temp_subject->time_indeterminate_notrunning);
				printf(" \"%s\": %2.3f, ", hheader[29], percent_time_indeterminate_notrunning);
				printf(" \"%s\": %lu, ", hheader[30], temp_subject->time_indeterminate_nodata);
				printf(" \"%s\": %2.3f, ", hheader[31], percent_time_indeterminate_nodata);
				printf(" \"%s\": %lu, ", hheader[32], time_indeterminate);
				printf(" \"%s\": %2.3f, ", hheader[33], percent_time_indeterminate);

				/* total times */
				printf(" \"%s\": %lu, ", hheader[34], total_time);
				printf(" \"%s\": 100.000, ", hheader[35]);
				printf(" \"%s\": 100.000, \n", hheader[36]);

				printf("\"服务状态细分\": [\n");

			} else if (content_type == XML_CONTENT) {

				printf("<host_availability>\n");
				printf("<host name=\"%s\">\n", temp_subject->host_name);

				/* up times */
				printf("<%s>%lu</%s>\n", hheader[1], temp_subject->scheduled_time_up, hheader[1]);
				printf("<%s>%2.3f</%s>\n", hheader[2], percent_time_up_scheduled, hheader[2]);
				printf("<%s>%2.3f</%s>\n", hheader[3], percent_time_up_scheduled_known, hheader[3]);
				printf("<%s>%lu</%s>\n", hheader[4], temp_subject->time_up - temp_subject->scheduled_time_up, hheader[4]);
				printf("<%s>%2.3f</%s>\n", hheader[5], percent_time_up_unscheduled, hheader[5]);
				printf("<%s>%2.3f</%s>\n", hheader[6], percent_time_up_unscheduled_known, hheader[6]);
				printf("<%s>%lu</%s>\n", hheader[7], temp_subject->time_up, hheader[7]);
				printf("<%s>%2.3f</%s>\n", hheader[8], percent_time_up, hheader[8]);
				printf("<%s>%2.3f</%s>\n", hheader[9], percent_time_up_known, hheader[9]);

				/* down times */
				printf("<%s>%lu</%s>\n", hheader[10], temp_subject->scheduled_time_down, hheader[10]);
				printf("<%s>%2.3f</%s>\n", hheader[11], percent_time_down_scheduled, hheader[11]);
				printf("<%s>%2.3f</%s>\n", hheader[12], percent_time_down_scheduled_known, hheader[12]);
				printf("<%s>%lu</%s>\n", hheader[13], temp_subject->time_down - temp_subject->scheduled_time_down, hheader[13]);
				printf("<%s>%2.3f</%s>\n", hheader[14], percent_time_down_unscheduled, hheader[14]);
				printf("<%s>%2.3f</%s>\n", hheader[15], percent_time_down_unscheduled_known, hheader[15]);
				printf("<%s>%lu</%s>\n", hheader[16], temp_subject->time_down, hheader[16]);
				printf("<%s>%2.3f</%s>\n", hheader[17], percent_time_down, hheader[17]);
				printf("<%s>%2.3f</%s>\n", hheader[18], percent_time_down_known, hheader[18]);

				/* unreachable times */
				printf("<%s>%lu</%s>\n", hheader[19], temp_subject->scheduled_time_unreachable, hheader[19]);
				printf("<%s>%2.3f</%s>\n", hheader[20], percent_time_unreachable_scheduled, hheader[20]);
				printf("<%s>%2.3f</%s>\n", hheader[21], percent_time_unreachable_scheduled_known, hheader[21]);
				printf("<%s>%lu</%s>\n", hheader[22], temp_subject->time_unreachable - temp_subject->scheduled_time_unreachable, hheader[22]);
				printf("<%s>%2.3f</%s>\n", hheader[23], percent_time_unreachable_unscheduled, hheader[23]);
				printf("<%s>%2.3f</%s>\n", hheader[24], percent_time_unreachable_unscheduled_known, hheader[24]);
				printf("<%s>%lu</%s>\n", hheader[25], temp_subject->time_unreachable, hheader[25]);
				printf("<%s>%2.3f</%s>\n", hheader[26], percent_time_unreachable, hheader[26]);
				printf("<%s>%2.3f</%s>\n", hheader[27], percent_time_unreachable_known, hheader[27]);

				/* indeterminate times */
				printf("<%s>%lu</%s>\n", hheader[28], temp_subject->time_indeterminate_notrunning, hheader[28]);
				printf("<%s>%2.3f</%s>\n", hheader[29], percent_time_indeterminate_notrunning, hheader[29]);
				printf("<%s>%lu</%s>\n", hheader[30], temp_subject->time_indeterminate_nodata, hheader[30]);
				printf("<%s>%2.3f</%s>\n", hheader[31], percent_time_indeterminate_nodata, hheader[31]);
				printf("<%s>%lu</%s>\n", hheader[32], time_indeterminate, hheader[32]);
				printf("<%s>%2.3f</%s>\n", hheader[33], percent_time_indeterminate, hheader[33]);

				/* total times */
				printf("<%s>%lu</%s>\n", hheader[34], total_time, hheader[34]);
				printf("<%s>100.000</%s>\n", hheader[35], hheader[35]);
				printf("<%s>100.000</%s>\n", hheader[36], hheader[36]);

				printf("<service_state_breakdowns>\n");
			}

			for (temp_subject = subject_list; temp_subject != NULL; temp_subject = temp_subject->next) {

				if (temp_subject->type != SERVICE_SUBJECT)
					continue;

				temp_service = find_service(temp_subject->host_name, temp_subject->service_description);
				if (temp_service == NULL)
					continue;

				/* the user isn't authorized to view this service */
				if (is_authorized_for_service(temp_service, &current_authdata) == FALSE)
					continue;

				current_subject++;

				if (odd) {
					odd = 0;
					bgclass = "Odd";
				} else {
					odd = 1;
					bgclass = "Even";
				}

				/* reset variables */
				percent_time_ok = 0.0;
				percent_time_warning = 0.0;
				percent_time_unknown = 0.0;
				percent_time_critical = 0.0;
				percent_time_indeterminate = 0.0;
				percent_time_ok_known = 0.0;
				percent_time_warning_known = 0.0;
				percent_time_unknown_known = 0.0;
				percent_time_critical_known = 0.0;

				time_determinate = temp_subject->time_ok + temp_subject->time_warning + temp_subject->time_unknown + temp_subject->time_critical;
				time_indeterminate = total_time - time_determinate;

				if (total_time > 0) {
					percent_time_ok = (double)(((double)temp_subject->time_ok * 100.0) / (double)total_time);
					percent_time_warning = (double)(((double)temp_subject->time_warning * 100.0) / (double)total_time);
					percent_time_unknown = (double)(((double)temp_subject->time_unknown * 100.0) / (double)total_time);
					percent_time_critical = (double)(((double)temp_subject->time_critical * 100.0) / (double)total_time);
					percent_time_indeterminate = (double)(((double)time_indeterminate * 100.0) / (double)total_time);
					if (time_determinate > 0) {
						percent_time_ok_known = (double)(((double)temp_subject->time_ok * 100.0) / (double)time_determinate);
						percent_time_warning_known = (double)(((double)temp_subject->time_warning * 100.0) / (double)time_determinate);
						percent_time_unknown_known = (double)(((double)temp_subject->time_unknown * 100.0) / (double)time_determinate);
						percent_time_critical_known = (double)(((double)temp_subject->time_critical * 100.0) / (double)time_determinate);
					}
				}

				if (content_type == HTML_CONTENT) {
					printf("<tr CLASS='data%s'><td CLASS='data%s'>", bgclass, bgclass);
					service_report_url(temp_subject->host_name, temp_subject->service_description, temp_subject->service_description);
					printf("</td><td CLASS='serviceOK'>%2.3f%% (%2.3f%%)</td><td CLASS='serviceWARNING'>%2.3f%% (%2.3f%%)</td><td CLASS='serviceUNKNOWN'>%2.3f%% (%2.3f%%)</td><td class='serviceCRITICAL'>%2.3f%% (%2.3f%%)</td><td class='data%s' align='center'>%2.3f%%</td></tr>\n", percent_time_ok, percent_time_ok_known, percent_time_warning, percent_time_warning_known, percent_time_unknown, percent_time_unknown_known, percent_time_critical, percent_time_critical_known, bgclass, percent_time_indeterminate);
				} else if (content_type == XML_CONTENT) {
					printf("<service name=\"%s\">\n", temp_subject->service_description);
					printf("<percent_time_ok>%2.3f</percent_time_ok>\n", percent_time_ok);
					printf("<percent_time_ok_known>%2.3f</percent_time_ok_known>\n", percent_time_ok_known);
					printf("<percent_time_warning>%2.3f</percent_time_warning>\n", percent_time_warning);
					printf("<percent_time_warning_known>%2.3f</percent_time_warning_known>\n", percent_time_warning_known);
					printf("<percent_time_unknown>%2.3f</percent_time_unknown>\n", percent_time_unknown);
					printf("<percent_time_unknown_known>%2.3f</percent_time_unknown_known>\n", percent_time_unknown_known);
					printf("<percent_time_critical>%2.3f</percent_time_critical>\n", percent_time_critical);
					printf("<percent_time_critical_known>%2.3f</percent_time_critical_known>\n", percent_time_critical_known);
					printf("<percent_time_indeterminate>%2.3f</percent_time_indeterminate>\n", percent_time_indeterminate);
					printf("</service>");
				} else {
					if (json_start != TRUE)
						printf(",\n");
					json_start = FALSE;

					printf(" {\"服务描述\": \"%s\", ", temp_service->description);
					printf(" \"服务显示名称\": \"%s\", ", (temp_service->display_name != NULL) ? json_encode(temp_service->display_name) : json_encode(temp_service->description));
					printf(" \"正常时间百分比\": %2.3f, ", percent_time_ok);
					printf(" \"已知正常时间百分比\": %2.3f, ", percent_time_ok_known);
					printf(" \"警报时间百分比\": %2.3f, ", percent_time_warning);
					printf(" \"已知警报时间百分比\": %2.3f, ", percent_time_warning_known);
					printf(" \"未知时间百分比\": %2.3f, ", percent_time_unknown);
					printf(" \"已知未知时间百分比\": %2.3f, ", percent_time_unknown_known);
					printf(" \"严重时间百分比\": %2.3f, ", percent_time_critical);
					printf(" \"已知严重时间百分比\": %2.3f, ", percent_time_critical_known);
					printf(" \"未决时间百分比\": %2.3f } ", percent_time_indeterminate);
				}

				get_running_average(&average_percent_time_ok, percent_time_ok, current_subject);
				get_running_average(&average_percent_time_ok_known, percent_time_ok_known, current_subject);
				get_running_average(&average_percent_time_unknown, percent_time_unknown, current_subject);
				get_running_average(&average_percent_time_unknown_known, percent_time_unknown_known, current_subject);
				get_running_average(&average_percent_time_warning, percent_time_warning, current_subject);
				get_running_average(&average_percent_time_warning_known, percent_time_warning_known, current_subject);
				get_running_average(&average_percent_time_critical, percent_time_critical, current_subject);
				get_running_average(&average_percent_time_critical_known, percent_time_critical_known, current_subject);
				get_running_average(&average_percent_time_indeterminate, percent_time_indeterminate, current_subject);
			}

			/* display average stats */
			if (odd) {
				odd = 0;
				bgclass = "Odd";
			} else {
				odd = 1;
				bgclass = "Even";
			}

			if (content_type == HTML_CONTENT) {
				printf("<tr CLASS='data%s'><td CLASS='data%s'>平均</td><td CLASS='serviceOK'>%2.3f%% (%2.3f%%)</td><td CLASS='serviceWARNING'>%2.3f%% (%2.3f%%)</td><td CLASS='serviceUNKNOWN'>%2.3f%% (%2.3f%%)</td><td class='serviceCRITICAL'>%2.3f%% (%2.3f%%)</td><td class='data%s' align='center'>%2.3f%%</td></tr>\n", bgclass, bgclass, average_percent_time_ok, average_percent_time_ok_known, average_percent_time_warning, average_percent_time_warning_known, average_percent_time_unknown, average_percent_time_unknown_known, average_percent_time_critical, average_percent_time_critical_known, bgclass, average_percent_time_indeterminate);
				printf("</table>\n");
			} else if (content_type == XML_CONTENT) {
				printf("<all_services_average>\n");
				printf("<average_percent_time_ok>%2.3f</average_percent_time_ok>\n", average_percent_time_ok);
				printf("<average_percent_time_ok_known>%2.3f</average_percent_time_ok_known>\n", average_percent_time_ok_known);
				printf("<average_percent_time_warning>%2.3f</average_percent_time_warning>\n", average_percent_time_warning);
				printf("<average_percent_time_warning_known>%2.3f</average_percent_time_warning_known>\n", average_percent_time_warning_known);
				printf("<average_percent_time_unknown>%2.3f</average_percent_time_unknown>\n", average_percent_time_unknown);
				printf("<average_percent_time_unknown_known>%2.3f</average_percent_time_unknown_known>\n", average_percent_time_unknown_known);
				printf("<average_percent_time_critical>%2.3f</average_percent_time_critical>\n", average_percent_time_critical);
				printf("<average_percent_time_critical_known>%2.3f</average_percent_time_critical_known>\n", average_percent_time_critical_known);
				printf("<average_percent_time_indeterminate>%2.3f</average_percent_time_indeterminate>\n", average_percent_time_indeterminate);
				printf("</all_services_average>\n");
				printf("</service_state_breakdowns>\n");
			} else {
				printf("],\n");
				printf(" \"所有服务平均值\": [ {");
				printf(" \"正常时间平均百分比\": %2.3f, ", average_percent_time_ok);
				printf(" \"已知正常时间平均百分比\": %2.3f, ", average_percent_time_ok_known);
				printf(" \"警报时间平均百分比\": %2.3f, ", average_percent_time_warning);
				printf(" \"已知警报时间平均百分比\": %2.3f, ", average_percent_time_warning_known);
				printf(" \"未知时间平均百分比\": %2.3f, ", average_percent_time_unknown);
				printf(" \"已知未知时间平均百分比\": %2.3f, ", average_percent_time_unknown_known);
				printf(" \"严重时间平均百分比\": %2.3f, ", average_percent_time_critical);
				printf(" \"已知严重时间平均百分比\": %2.3f, ", average_percent_time_critical_known);
				printf(" \"未决时间平均百分比\": %2.3f } ], \n", average_percent_time_indeterminate);
			}

			/* write log entries for the host */
			temp_subject = find_subject(HOST_SUBJECT, host_name, NULL);
			write_log_entries(temp_subject);

			if (content_type == JSON_CONTENT)
				printf("}\n]\n}");
			else if (content_type == XML_CONTENT) {
				printf("</host>\n");
				printf("</host_availability>\n");
			}

		} else if (content_type == CSV_CONTENT) {

			for (i = 0; i < hheader_num -1 ; i++)
				printf("%s%s%s%s", csv_data_enclosure, hheader[i], csv_data_enclosure, csv_delimiter);

			printf("\n");

			/* host name */
			printf("%s%s%s%s", csv_data_enclosure, temp_subject->host_name, csv_data_enclosure, csv_delimiter);

			/* up times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_up, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_scheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_scheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_up - temp_subject->scheduled_time_up, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_unscheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_unscheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_up, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_known, csv_data_enclosure, csv_delimiter);

			/* down times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_down, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_scheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_scheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_down - temp_subject->scheduled_time_down, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_unscheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_unscheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_down, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_known, csv_data_enclosure, csv_delimiter);

			/* unreachable times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_unreachable, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_scheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_scheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_unreachable - temp_subject->scheduled_time_unreachable, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_unscheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_unscheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_unreachable, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_known, csv_data_enclosure, csv_delimiter);

			/* indeterminate times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_indeterminate_notrunning, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate_notrunning, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_indeterminate_nodata, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate_nodata, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, time_indeterminate, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate, csv_data_enclosure, csv_delimiter);

			/* total times */
			printf("%s%lu%s%s", csv_data_enclosure, total_time, csv_data_enclosure, csv_delimiter);
			printf("%s100.000%%%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s100.000%%%s", csv_data_enclosure, csv_data_enclosure);

			printf("\n");
		}
	}


	/* display data for all hosts */
	else {

		if (content_type == HTML_CONTENT) {

			printf("<BR><BR>\n");
			printf("<DIV ALIGN=CENTER CLASS='dataTitle'>主机状态细分:</DIV>\n");

			printf("<TABLE BORDER=0 CLASS='data' align='center'>\n");
			printf("<TR><TH CLASS='data'>Host</TH><TH CLASS='data'>%% 正常时间</TH><TH CLASS='data'>%% 宕机时间</TH><TH CLASS='data'>%% 不可达时间</TH><TH CLASS='data'>%% 未决时间</TH></TR>\n");
		} else if (content_type == JSON_CONTENT) {
			printf("\"主机可用性\": {\n");
			printf("\"主机\": [\n");
		} else if (content_type == XML_CONTENT) {
			printf("<host_availability>\n");
		} else if (content_type == CSV_CONTENT) {

			for (i = 0; i < hheader_num -1; i++)
				printf("%s%s%s%s", csv_data_enclosure, hheader[i], csv_data_enclosure, csv_delimiter);

			printf("\n");
		}


		for (temp_subject = subject_list; temp_subject != NULL; temp_subject = temp_subject->next) {

			if (temp_subject->type != HOST_SUBJECT)
				continue;

			temp_host = find_host(temp_subject->host_name);
			if (temp_host == NULL)
				continue;

			/* the user isn't authorized to view this host */
			if (is_authorized_for_host(temp_host, &current_authdata) == FALSE)
				continue;

			current_subject++;

			time_determinate = temp_subject->time_up + temp_subject->time_down + temp_subject->time_unreachable;
			time_indeterminate = total_time - time_determinate;

			/* adjust indeterminate time due to insufficient data (not all was caught) */
			temp_subject->time_indeterminate_nodata = time_indeterminate - temp_subject->time_indeterminate_notrunning;

			/* initialize values */
			percent_time_up = 0.0;
			percent_time_up_scheduled = 0.0;
			percent_time_up_unscheduled = 0.0;
			percent_time_down = 0.0;
			percent_time_down_scheduled = 0.0;
			percent_time_down_unscheduled = 0.0;
			percent_time_unreachable = 0.0;
			percent_time_unreachable_scheduled = 0.0;
			percent_time_unreachable_unscheduled = 0.0;
			percent_time_indeterminate = 0.0;
			percent_time_indeterminate_scheduled = 0.0;
			percent_time_indeterminate_unscheduled = 0.0;
			percent_time_indeterminate_notrunning = 0.0;
			percent_time_indeterminate_nodata = 0.0;
			percent_time_up_known = 0.0;
			percent_time_up_scheduled_known = 0.0;
			percent_time_up_unscheduled_known = 0.0;
			percent_time_down_known = 0.0;
			percent_time_down_scheduled_known = 0.0;
			percent_time_down_unscheduled_known = 0.0;
			percent_time_unreachable_known = 0.0;
			percent_time_unreachable_scheduled_known = 0.0;
			percent_time_unreachable_unscheduled_known = 0.0;

			if (total_time > 0) {
				percent_time_up = (double)(((double)temp_subject->time_up * 100.0) / (double)total_time);
				percent_time_up_scheduled = (double)(((double)temp_subject->scheduled_time_up * 100.0) / (double)total_time);
				percent_time_up_unscheduled = percent_time_up - percent_time_up_scheduled;
				percent_time_down = (double)(((double)temp_subject->time_down * 100.0) / (double)total_time);
				percent_time_down_scheduled = (double)(((double)temp_subject->scheduled_time_down * 100.0) / (double)total_time);
				percent_time_down_unscheduled = percent_time_down - percent_time_down_scheduled;
				percent_time_unreachable = (double)(((double)temp_subject->time_unreachable * 100.0) / (double)total_time);
				percent_time_unreachable_scheduled = (double)(((double)temp_subject->scheduled_time_unreachable * 100.0) / (double)total_time);
				percent_time_unreachable_unscheduled = percent_time_unreachable - percent_time_unreachable_scheduled;
				percent_time_indeterminate = (double)(((double)time_indeterminate * 100.0) / (double)total_time);
				percent_time_indeterminate_scheduled = (double)(((double)temp_subject->scheduled_time_indeterminate * 100.0) / (double)total_time);
				percent_time_indeterminate_unscheduled = percent_time_indeterminate - percent_time_indeterminate_scheduled;
				percent_time_indeterminate_notrunning = (double)(((double)temp_subject->time_indeterminate_notrunning * 100.0) / (double)total_time);
				percent_time_indeterminate_nodata = (double)(((double)temp_subject->time_indeterminate_nodata * 100.0) / (double)total_time);
				if (time_determinate > 0) {
					percent_time_up_known = (double)(((double)temp_subject->time_up * 100.0) / (double)time_determinate);
					percent_time_up_scheduled_known = (double)(((double)temp_subject->scheduled_time_up * 100.0) / (double)time_determinate);
					percent_time_up_unscheduled_known = percent_time_up_known - percent_time_up_scheduled_known;
					percent_time_down_known = (double)(((double)temp_subject->time_down * 100.0) / (double)time_determinate);
					percent_time_down_scheduled_known = (double)(((double)temp_subject->scheduled_time_down * 100.0) / (double)time_determinate);
					percent_time_down_unscheduled_known = percent_time_down_known - percent_time_down_scheduled_known;
					percent_time_unreachable_known = (double)(((double)temp_subject->time_unreachable * 100.0) / (double)time_determinate);
					percent_time_unreachable_scheduled_known = (double)(((double)temp_subject->scheduled_time_unreachable * 100.0) / (double)time_determinate);
					percent_time_unreachable_unscheduled_known = percent_time_unreachable_known - percent_time_unreachable_scheduled_known;
				}
			}

			if (content_type == HTML_CONTENT) {

				if (odd) {
					odd = 0;
					bgclass = "Odd";
				} else {
					odd = 1;
					bgclass = "Even";
				}

				printf("<tr CLASS='data%s'><td CLASS='data%s'>", bgclass, bgclass);
				host_report_url(temp_subject->host_name, temp_subject->host_name);
				printf("</td><td CLASS='hostUP'>%2.3f%% (%2.3f%%)</td><td CLASS='hostDOWN'>%2.3f%% (%2.3f%%)</td><td CLASS='hostUNREACHABLE'>%2.3f%% (%2.3f%%)</td><td class='data%s' align='center'>%2.3f%%</td></tr>\n", percent_time_up, percent_time_up_known, percent_time_down, percent_time_down_known, percent_time_unreachable, percent_time_unreachable_known, bgclass, percent_time_indeterminate);
			} else if (content_type == JSON_CONTENT) {
				if (json_start != TRUE)
					printf(",\n");

				/* host name */
				printf("{ \"%s\": \"%s\", ", hheader[0], json_encode(temp_subject->host_name));
				printf("{ \"%s\": \"%s\", ", hheader[37], (temp_host->display_name != NULL) ? json_encode(temp_host->display_name) : json_encode(temp_host->name));

				/* up times */
				printf(" \"%s\": %lu, ", hheader[1], temp_subject->scheduled_time_up);
				printf(" \"%s\": %2.3f, ", hheader[2], percent_time_up_scheduled);
				printf(" \"%s\": %2.3f, ", hheader[3], percent_time_up_scheduled_known);
				printf(" \"%s\": %lu, ", hheader[4], temp_subject->time_up - temp_subject->scheduled_time_up);
				printf(" \"%s\": %2.3f, ", hheader[5], percent_time_up_unscheduled);
				printf(" \"%s\": %2.3f, ", hheader[6], percent_time_up_unscheduled_known);
				printf(" \"%s\": %lu, ", hheader[7], temp_subject->time_up);
				printf(" \"%s\": %2.3f, ", hheader[8], percent_time_up);
				printf(" \"%s\": %2.3f, ", hheader[9], percent_time_up_known);

				/* down times */
				printf(" \"%s\": %lu, ", hheader[10], temp_subject->scheduled_time_down);
				printf(" \"%s\": %2.3f, ", hheader[11], percent_time_down_scheduled);
				printf(" \"%s\": %2.3f, ", hheader[12], percent_time_down_scheduled_known);
				printf(" \"%s\": %lu, ", hheader[13], temp_subject->time_down - temp_subject->scheduled_time_down);
				printf(" \"%s\": %2.3f, ", hheader[14], percent_time_down_unscheduled);
				printf(" \"%s\": %2.3f, ", hheader[15], percent_time_down_unscheduled_known);
				printf(" \"%s\": %lu, ", hheader[16], temp_subject->time_down);
				printf(" \"%s\": %2.3f, ", hheader[17], percent_time_down);
				printf(" \"%s\": %2.3f, ", hheader[18], percent_time_down_known);

				/* unreachable times */
				printf(" \"%s\": %lu, ", hheader[19], temp_subject->scheduled_time_unreachable);
				printf(" \"%s\": %2.3f, ", hheader[20], percent_time_unreachable_scheduled);
				printf(" \"%s\": %2.3f, ", hheader[21], percent_time_unreachable_scheduled_known);
				printf(" \"%s\": %lu, ", hheader[22], temp_subject->time_unreachable - temp_subject->scheduled_time_unreachable);
				printf(" \"%s\": %2.3f, ", hheader[23], percent_time_unreachable_unscheduled);
				printf(" \"%s\": %2.3f, ", hheader[24], percent_time_unreachable_unscheduled_known);
				printf(" \"%s\": %lu, ", hheader[25], temp_subject->time_unreachable);
				printf(" \"%s\": %2.3f, ", hheader[26], percent_time_unreachable);
				printf(" \"%s\": %2.3f, ", hheader[27], percent_time_unreachable_known);

				/* indeterminate times */
				printf(" \"%s\": %lu, ", hheader[28], temp_subject->time_indeterminate_notrunning);
				printf(" \"%s\": %2.3f, ", hheader[29], percent_time_indeterminate_notrunning);
				printf(" \"%s\": %lu, ", hheader[30], temp_subject->time_indeterminate_nodata);
				printf(" \"%s\": %2.3f, ", hheader[31], percent_time_indeterminate_nodata);
				printf(" \"%s\": %lu, ", hheader[32], time_indeterminate);
				printf(" \"%s\": %2.3f, ", hheader[33], percent_time_indeterminate);

				/* total times */
				printf(" \"%s\": %lu, ", hheader[34], total_time);
				printf(" \"%s\": 100.000, ", hheader[35]);
				printf(" \"%s\": 100.000} ", hheader[36]);

				json_start = FALSE;

			} else if (content_type == XML_CONTENT) {

				printf("<host name=\"%s\">\n", temp_subject->host_name);

				/* up times */
				printf("<%s>%lu</%s>\n", hheader[1], temp_subject->scheduled_time_up, hheader[1]);
				printf("<%s>%2.3f</%s>\n", hheader[2], percent_time_up_scheduled, hheader[2]);
				printf("<%s>%2.3f</%s>\n", hheader[3], percent_time_up_scheduled_known, hheader[3]);
				printf("<%s>%lu</%s>\n", hheader[4], temp_subject->time_up - temp_subject->scheduled_time_up, hheader[4]);
				printf("<%s>%2.3f</%s>\n", hheader[5], percent_time_up_unscheduled, hheader[5]);
				printf("<%s>%2.3f</%s>\n", hheader[6], percent_time_up_unscheduled_known, hheader[6]);
				printf("<%s>%lu</%s>\n", hheader[7], temp_subject->time_up, hheader[7]);
				printf("<%s>%2.3f</%s>\n", hheader[8], percent_time_up, hheader[8]);
				printf("<%s>%2.3f</%s>\n", hheader[9], percent_time_up_known, hheader[9]);

				/* down times */
				printf("<%s>%lu</%s>\n", hheader[10], temp_subject->scheduled_time_down, hheader[10]);
				printf("<%s>%2.3f</%s>\n", hheader[11], percent_time_down_scheduled, hheader[11]);
				printf("<%s>%2.3f</%s>\n", hheader[12], percent_time_down_scheduled_known, hheader[12]);
				printf("<%s>%lu</%s>\n", hheader[13], temp_subject->time_down - temp_subject->scheduled_time_down, hheader[13]);
				printf("<%s>%2.3f</%s>\n", hheader[14], percent_time_down_unscheduled, hheader[14]);
				printf("<%s>%2.3f</%s>\n", hheader[15], percent_time_down_unscheduled_known, hheader[15]);
				printf("<%s>%lu</%s>\n", hheader[16], temp_subject->time_down, hheader[16]);
				printf("<%s>%2.3f</%s>\n", hheader[17], percent_time_down, hheader[17]);
				printf("<%s>%2.3f</%s>\n", hheader[18], percent_time_down_known, hheader[18]);

				/* unreachable times */
				printf("<%s>%lu</%s>\n", hheader[19], temp_subject->scheduled_time_unreachable, hheader[19]);
				printf("<%s>%2.3f</%s>\n", hheader[20], percent_time_unreachable_scheduled, hheader[20]);
				printf("<%s>%2.3f</%s>\n", hheader[21], percent_time_unreachable_scheduled_known, hheader[21]);
				printf("<%s>%lu</%s>\n", hheader[22], temp_subject->time_unreachable - temp_subject->scheduled_time_unreachable, hheader[22]);
				printf("<%s>%2.3f</%s>\n", hheader[23], percent_time_unreachable_unscheduled, hheader[23]);
				printf("<%s>%2.3f</%s>\n", hheader[24], percent_time_unreachable_unscheduled_known, hheader[24]);
				printf("<%s>%lu</%s>\n", hheader[25], temp_subject->time_unreachable, hheader[25]);
				printf("<%s>%2.3f</%s>\n", hheader[26], percent_time_unreachable, hheader[26]);
				printf("<%s>%2.3f</%s>\n", hheader[27], percent_time_unreachable_known, hheader[27]);

				/* indeterminate times */
				printf("<%s>%lu</%s>\n", hheader[28], temp_subject->time_indeterminate_notrunning, hheader[28]);
				printf("<%s>%2.3f</%s>\n", hheader[29], percent_time_indeterminate_notrunning, hheader[29]);
				printf("<%s>%lu</%s>\n", hheader[30], temp_subject->time_indeterminate_nodata, hheader[30]);
				printf("<%s>%2.3f</%s>\n", hheader[31], percent_time_indeterminate_nodata, hheader[31]);
				printf("<%s>%lu</%s>\n", hheader[32], time_indeterminate, hheader[32]);
				printf("<%s>%2.3f</%s>\n", hheader[33], percent_time_indeterminate, hheader[33]);

				/* total times */
				printf("<%s>%lu</%s>\n", hheader[34], total_time, hheader[34]);
				printf("<%s>100.000</%s>\n", hheader[35], hheader[35]);
				printf("<%s>100.000</%s>\n", hheader[36], hheader[36]);

				printf("</host>\n");
			} else if (content_type == CSV_CONTENT) {

				/* host name */
				printf("%s%s%s%s", csv_data_enclosure, temp_subject->host_name, csv_data_enclosure, csv_delimiter);

				/* up times */
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_up, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_scheduled, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_scheduled_known, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_up - temp_subject->scheduled_time_up, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_unscheduled, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_unscheduled_known, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_up, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_up_known, csv_data_enclosure, csv_delimiter);

				/* down times */
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_down, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_scheduled, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_scheduled_known, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_down - temp_subject->scheduled_time_down, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_unscheduled, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_unscheduled_known, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_down, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_down_known, csv_data_enclosure, csv_delimiter);

				/* unreachable times */
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_unreachable, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_scheduled, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_scheduled_known, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_unreachable - temp_subject->scheduled_time_unreachable, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_unscheduled, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_unscheduled_known, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_unreachable, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unreachable_known, csv_data_enclosure, csv_delimiter);

				/* indeterminate times */
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_indeterminate_notrunning, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate_notrunning, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_indeterminate_nodata, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate_nodata, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, time_indeterminate, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate, csv_data_enclosure, csv_delimiter);

				/* total times */
				printf("%s%lu%s%s", csv_data_enclosure, total_time, csv_data_enclosure, csv_delimiter);
				printf("%s100.000%%%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
				printf("%s100.000%%%s", csv_data_enclosure, csv_data_enclosure);

				printf("\n");
			}

			get_running_average(&average_percent_time_up, percent_time_up, current_subject);
			get_running_average(&average_percent_time_up_known, percent_time_up_known, current_subject);
			get_running_average(&average_percent_time_down, percent_time_down, current_subject);
			get_running_average(&average_percent_time_down_known, percent_time_down_known, current_subject);
			get_running_average(&average_percent_time_unreachable, percent_time_unreachable, current_subject);
			get_running_average(&average_percent_time_unreachable_known, percent_time_unreachable_known, current_subject);
			get_running_average(&average_percent_time_indeterminate, percent_time_indeterminate, current_subject);
		}

		if (content_type == HTML_CONTENT) {

			/* average statistics */
			if (odd) {
				odd = 0;
				bgclass = "Odd";
			} else {
				odd = 1;
				bgclass = "Even";
			}
			printf("<tr CLASS='data%s'><td CLASS='data%s'>平均</td><td CLASS='hostUP'>%2.3f%% (%2.3f%%)</td><td CLASS='hostDOWN'>%2.3f%% (%2.3f%%)</td><td CLASS='hostUNREACHABLE'>%2.3f%% (%2.3f%%)</td><td class='data%s'  align='center'>%2.3f%%</td></tr>", bgclass, bgclass, average_percent_time_up, average_percent_time_up_known, average_percent_time_down, average_percent_time_down_known, average_percent_time_unreachable, average_percent_time_unreachable_known, bgclass, average_percent_time_indeterminate);
			printf("</table>\n");
		} else if (content_type == JSON_CONTENT) {
			printf(" ],\n");
			printf("\"所有主机平均值\": [ {");
			printf("\"运行时间平均百分比\": %2.3f, ", average_percent_time_up);
			printf("\"已知运行时间平均百分比\": %2.3f, ", average_percent_time_up_known);
			printf("\"宕机时间平均百分比\": %2.3f, ", average_percent_time_down);
			printf("\"已知宕机时间平均百分比\": %2.3f, ", average_percent_time_down_known);
			printf("\"不可达时间平均百分比\": %2.3f, ", average_percent_time_unreachable);
			printf("\"已知不可达时间平均百分比\": %2.3f, ", average_percent_time_unreachable_known);
			printf("\"未决时间平均百分比\": %2.3f } ] }\n", average_percent_time_indeterminate);
		} else if (content_type == XML_CONTENT) {
			printf("<all_hosts_average>\n");
			printf("<average_percent_time_up>%2.3f</average_percent_time_up>\n", average_percent_time_up);
			printf("<average_percent_time_up_known>%2.3f</average_percent_time_up_known>\n", average_percent_time_up_known);
			printf("<average_percent_time_down>%2.3f</average_percent_time_down>\n", average_percent_time_down);
			printf("<average_percent_time_down_known>%2.3f</average_percent_time_down_known>\n", average_percent_time_down_known);
			printf("<average_percent_time_unreachable>%2.3f</average_percent_time_unreachable>\n", average_percent_time_unreachable);
			printf("<average_percent_time_unreachable_known>%2.3f</average_percent_time_unreachable_known>\n", average_percent_time_unreachable_known);
			printf("<average_percent_time_indeterminate>%2.3f</average_percent_time_indeterminate>\n", average_percent_time_indeterminate);
			printf("</all_hosts_average>\n");
			printf("</host_availability>\n");
		} else if (content_type == CSV_CONTENT) {
			/* average */
			/* left for future rework */
		}
	}

	return;
}


/* display service availability */
void display_service_availability(void) {
	unsigned long total_time;
	unsigned long time_determinate;
	unsigned long time_indeterminate;
	avail_subject *temp_subject;
	service *temp_service;
	host *temp_host;
	int days, hours, minutes, seconds;
	char time_ok_string[48];
	char time_warning_string[48];
	char time_unknown_string[48];
	char time_critical_string[48];
	char time_indeterminate_string[48];
	char time_determinate_string[48];
	char total_time_string[48];
	double percent_time_ok = 0.0;
	double percent_time_warning = 0.0;
	double percent_time_unknown = 0.0;
	double percent_time_critical = 0.0;
	double percent_time_indeterminate = 0.0;
	double percent_time_ok_known = 0.0;
	double percent_time_warning_known = 0.0;
	double percent_time_unknown_known = 0.0;
	double percent_time_critical_known = 0.0;

	char time_critical_scheduled_string[48];
	char time_critical_unscheduled_string[48];
	double percent_time_critical_scheduled = 0.0;
	double percent_time_critical_unscheduled = 0.0;
	double percent_time_critical_scheduled_known = 0.0;
	double percent_time_critical_unscheduled_known = 0.0;
	char time_unknown_scheduled_string[48];
	char time_unknown_unscheduled_string[48];
	double percent_time_unknown_scheduled = 0.0;
	double percent_time_unknown_unscheduled = 0.0;
	double percent_time_unknown_scheduled_known = 0.0;
	double percent_time_unknown_unscheduled_known = 0.0;
	char time_warning_scheduled_string[48];
	char time_warning_unscheduled_string[48];
	double percent_time_warning_scheduled = 0.0;
	double percent_time_warning_unscheduled = 0.0;
	double percent_time_warning_scheduled_known = 0.0;
	double percent_time_warning_unscheduled_known = 0.0;
	char time_ok_scheduled_string[48];
	char time_ok_unscheduled_string[48];
	double percent_time_ok_scheduled = 0.0;
	double percent_time_ok_unscheduled = 0.0;
	double percent_time_ok_scheduled_known = 0.0;
	double percent_time_ok_unscheduled_known = 0.0;

	double average_percent_time_ok = 0.0;
	double average_percent_time_ok_known = 0.0;
	double average_percent_time_unknown = 0.0;
	double average_percent_time_unknown_known = 0.0;
	double average_percent_time_warning = 0.0;
	double average_percent_time_warning_known = 0.0;
	double average_percent_time_critical = 0.0;
	double average_percent_time_critical_known = 0.0;
	double average_percent_time_indeterminate = 0.0;

	int current_subject = 0;

	char time_indeterminate_scheduled_string[48];
	char time_indeterminate_unscheduled_string[48];
	double percent_time_indeterminate_scheduled = 0.0;
	double percent_time_indeterminate_unscheduled = 0.0;
	char time_indeterminate_notrunning_string[48];
	char time_indeterminate_nodata_string[48];
	double percent_time_indeterminate_notrunning = 0.0;
	double percent_time_indeterminate_nodata = 0.0;

	int odd = 1;
	int i = 0;
	char *bgclass = "";
	char last_host[128] = "";
	int json_start = TRUE;


	/* calculate total time during period based on timeperiod used for reporting */
	total_time = calculate_total_time(t1, t2);

	/* we're only getting data for one service */
	if (show_all_services == FALSE) {

		temp_subject = find_subject(SERVICE_SUBJECT, host_name, service_desc);
		if (temp_subject == NULL)
			return;

		temp_service = find_service(temp_subject->host_name, temp_subject->service_description);
		if (temp_service == NULL)
			return;

		/* the user isn't authorized to view this service */
		if (is_authorized_for_service(temp_service, &current_authdata) == FALSE)
			return;

		time_determinate = temp_subject->time_ok + temp_subject->time_warning + temp_subject->time_unknown + temp_subject->time_critical;
		time_indeterminate = total_time - time_determinate;

		/* adjust indeterminate time due to insufficient data (not all was caught) */
		temp_subject->time_indeterminate_nodata = time_indeterminate - temp_subject->time_indeterminate_notrunning;

		/* ok states */
		get_time_breakdown(temp_subject->time_ok, &days, &hours, &minutes, &seconds);
		snprintf(time_ok_string, sizeof(time_ok_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->scheduled_time_ok, &days, &hours, &minutes, &seconds);
		snprintf(time_ok_scheduled_string, sizeof(time_ok_scheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->time_ok - temp_subject->scheduled_time_ok, &days, &hours, &minutes, &seconds);
		snprintf(time_ok_unscheduled_string, sizeof(time_ok_unscheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);

		/* warning states */
		get_time_breakdown(temp_subject->time_warning, &days, &hours, &minutes, &seconds);
		snprintf(time_warning_string, sizeof(time_warning_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->scheduled_time_warning, &days, &hours, &minutes, &seconds);
		snprintf(time_warning_scheduled_string, sizeof(time_warning_scheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->time_warning - temp_subject->scheduled_time_warning, &days, &hours, &minutes, &seconds);
		snprintf(time_warning_unscheduled_string, sizeof(time_warning_unscheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);

		/* unknown states */
		get_time_breakdown(temp_subject->time_unknown, &days, &hours, &minutes, &seconds);
		snprintf(time_unknown_string, sizeof(time_unknown_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->scheduled_time_unknown, &days, &hours, &minutes, &seconds);
		snprintf(time_unknown_scheduled_string, sizeof(time_unknown_scheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->time_unknown - temp_subject->scheduled_time_unknown, &days, &hours, &minutes, &seconds);
		snprintf(time_unknown_unscheduled_string, sizeof(time_unknown_unscheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);

		/* critical states */
		get_time_breakdown(temp_subject->time_critical, &days, &hours, &minutes, &seconds);
		snprintf(time_critical_string, sizeof(time_critical_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->scheduled_time_critical, &days, &hours, &minutes, &seconds);
		snprintf(time_critical_scheduled_string, sizeof(time_critical_scheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->time_critical - temp_subject->scheduled_time_critical, &days, &hours, &minutes, &seconds);
		snprintf(time_critical_unscheduled_string, sizeof(time_critical_unscheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);

		/* indeterminate time */
		get_time_breakdown(time_indeterminate, &days, &hours, &minutes, &seconds);
		snprintf(time_indeterminate_string, sizeof(time_indeterminate_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->scheduled_time_indeterminate, &days, &hours, &minutes, &seconds);
		snprintf(time_indeterminate_scheduled_string, sizeof(time_indeterminate_scheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(time_indeterminate - temp_subject->scheduled_time_indeterminate, &days, &hours, &minutes, &seconds);
		snprintf(time_indeterminate_unscheduled_string, sizeof(time_indeterminate_unscheduled_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->time_indeterminate_notrunning, &days, &hours, &minutes, &seconds);
		snprintf(time_indeterminate_notrunning_string, sizeof(time_indeterminate_notrunning_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);
		get_time_breakdown(temp_subject->time_indeterminate_nodata, &days, &hours, &minutes, &seconds);
		snprintf(time_indeterminate_nodata_string, sizeof(time_indeterminate_nodata_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);

		get_time_breakdown(time_determinate, &days, &hours, &minutes, &seconds);
		snprintf(time_determinate_string, sizeof(time_determinate_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);

		get_time_breakdown(total_time, &days, &hours, &minutes, &seconds);
		snprintf(total_time_string, sizeof(total_time_string) - 1, "%02d天%02d时%02d分%02d秒", days, hours, minutes, seconds);

		if (total_time > 0) {
			percent_time_ok = (double)(((double)temp_subject->time_ok * 100.0) / (double)total_time);
			percent_time_ok_scheduled = (double)(((double)temp_subject->scheduled_time_ok * 100.0) / (double)total_time);
			percent_time_ok_unscheduled = percent_time_ok - percent_time_ok_scheduled;
			percent_time_warning = (double)(((double)temp_subject->time_warning * 100.0) / (double)total_time);
			percent_time_warning_scheduled = (double)(((double)temp_subject->scheduled_time_unknown * 100.0) / (double)total_time);
			percent_time_warning_unscheduled = percent_time_warning - percent_time_warning_scheduled;
			percent_time_unknown = (double)(((double)temp_subject->time_unknown * 100.0) / (double)total_time);
			percent_time_unknown_scheduled = (double)(((double)temp_subject->scheduled_time_unknown * 100.0) / (double)total_time);
			percent_time_unknown_unscheduled = percent_time_unknown - percent_time_unknown_scheduled;
			percent_time_critical = (double)(((double)temp_subject->time_critical * 100.0) / (double)total_time);
			percent_time_critical_scheduled = (double)(((double)temp_subject->scheduled_time_critical * 100.0) / (double)total_time);
			percent_time_critical_unscheduled = percent_time_critical - percent_time_critical_scheduled;
			percent_time_indeterminate = (double)(((double)time_indeterminate * 100.0) / (double)total_time);
			percent_time_indeterminate_scheduled = (double)(((double)temp_subject->scheduled_time_indeterminate * 100.0) / (double)total_time);
			percent_time_indeterminate_unscheduled = percent_time_indeterminate - percent_time_indeterminate_scheduled;
			percent_time_indeterminate_notrunning = (double)(((double)temp_subject->time_indeterminate_notrunning * 100.0) / (double)total_time);
			percent_time_indeterminate_nodata = (double)(((double)temp_subject->time_indeterminate_nodata * 100.0) / (double)total_time);
			if (time_determinate > 0) {
				percent_time_ok_known = (double)(((double)temp_subject->time_ok * 100.0) / (double)time_determinate);
				percent_time_ok_scheduled_known = (double)(((double)temp_subject->scheduled_time_ok * 100.0) / (double)time_determinate);
				percent_time_ok_unscheduled_known = percent_time_ok_known - percent_time_ok_scheduled_known;
				percent_time_warning_known = (double)(((double)temp_subject->time_warning * 100.0) / (double)time_determinate);
				percent_time_warning_scheduled_known = (double)(((double)temp_subject->scheduled_time_warning * 100.0) / (double)time_determinate);
				percent_time_warning_unscheduled_known = percent_time_warning_known - percent_time_warning_scheduled_known;
				percent_time_unknown_known = (double)(((double)temp_subject->time_unknown * 100.0) / (double)time_determinate);
				percent_time_unknown_scheduled_known = (double)(((double)temp_subject->scheduled_time_unknown * 100.0) / (double)time_determinate);
				percent_time_unknown_unscheduled_known = percent_time_unknown_known - percent_time_unknown_scheduled_known;
				percent_time_critical_known = (double)(((double)temp_subject->time_critical * 100.0) / (double)time_determinate);
				percent_time_critical_scheduled_known = (double)(((double)temp_subject->scheduled_time_critical * 100.0) / (double)time_determinate);
				percent_time_critical_unscheduled_known = percent_time_critical_known - percent_time_critical_scheduled_known;
			}
		}

		if (content_type == HTML_CONTENT) {

			printf("<DIV ALIGN=CENTER CLASS='dataTitle'>服务状态细分:</DIV>\n");
#ifdef USE_TRENDS
			printf("<p align='center'>\n");
			printf("<a href='%s?host=%s", TRENDS_CGI, url_encode(host_name));
			printf("&service=%s&t1=%lu&t2=%lu&includesoftstates=%s&assumestateretention=%s&assumeinitialstates=%s&assumestatesduringnotrunning=%s&initialassumedservicestate=%d&backtrack=%d'>", url_encode(service_desc), t1, t2, (include_soft_states == TRUE) ? "yes" : "no", (assume_state_retention == TRUE) ? "yes" : "no", (assume_initial_states == TRUE) ? "yes" : "no", (assume_states_during_notrunning == TRUE) ? "yes" : "no", initial_assumed_service_state, backtrack_archives);
			printf("<img src='%s?createimage&smallimage&host=%s", TRENDS_CGI, url_encode(host_name));
			printf("&service=%s&t1=%lu&t2=%lu&includesoftstates=%s&assumestateretention=%s&assumeinitialstates=%s&assumestatesduringnotrunning=%s&initialassumedservicestate=%d&backtrack=%d' border=1 alt='服务状态趋' title='服务状态趋' width='500' height='20'>", url_encode(service_desc), t1, t2, (include_soft_states == TRUE) ? "yes" : "no", (assume_state_retention == TRUE) ? "yes" : "no", (assume_initial_states == TRUE) ? "yes" : "no", (assume_states_during_notrunning == TRUE) ? "yes" : "no", initial_assumed_service_state, backtrack_archives);
			printf("</a><br>\n");
			printf("</p>\n");
#endif

			printf("<TABLE BORDER=0 CLASS='data' align='center'>\n");
			printf("<TR><TH CLASS='data'>状态</TH><TH CLASS='data'>类型/原因</TH><TH CLASS='data'>时间</TH><TH CLASS='data'>%% 总计时间</TH><TH CLASS='data'>%% Known Time</TH></TR>\n");

			/* ok states */
			printf("<tr CLASS='dataEven'><td CLASS='serviceOK' rowspan=3>正常</td>");
			printf("<td CLASS='dataEven'>未安排</td><td CLASS='dataEven'>%s</td><td CLASS='dataEven'>%2.3f%%</td><td CLASS='dataEven'>%2.3f%%</td></tr>\n", time_ok_unscheduled_string, percent_time_ok_unscheduled, percent_time_ok_unscheduled_known);
			printf("<tr CLASS='dataEven'><td CLASS='dataEven'>安排</td><td CLASS='dataEven'>%s</td><td CLASS='dataEven'>%2.3f%%</td><td CLASS='dataEven'>%2.3f%%</td></tr>\n", time_ok_scheduled_string, percent_time_ok_scheduled, percent_time_ok_scheduled_known);
			printf("<tr CLASS='serviceOK'><td CLASS='serviceOK'>总计</td><td CLASS='serviceOK'>%s</td><td CLASS='serviceOK'>%2.3f%%</td><td CLASS='serviceOK'>%2.3f%%</td></tr>\n", time_ok_string, percent_time_ok, percent_time_ok_known);

			/* warning states */
			printf("<tr CLASS='dataOdd'><td CLASS='serviceWARNING' rowspan=3>警报</td>");
			printf("<td CLASS='dataOdd'>未安排</td><td CLASS='dataOdd'>%s</td><td CLASS='dataOdd'>%2.3f%%</td><td CLASS='dataOdd'>%2.3f%%</td></tr>\n", time_warning_unscheduled_string, percent_time_warning_unscheduled, percent_time_warning_unscheduled_known);
			printf("<tr CLASS='dataOdd'><td CLASS='dataOdd'>安排</td><td CLASS='dataOdd'>%s</td><td CLASS='dataOdd'>%2.3f%%</td><td CLASS='dataOdd'>%2.3f%%</td></tr>\n", time_warning_scheduled_string, percent_time_warning_scheduled, percent_time_warning_scheduled_known);
			printf("<tr CLASS='serviceWARNING'><td CLASS='serviceWARNING'>总计</td><td CLASS='serviceWARNING'>%s</td><td CLASS='serviceWARNING'>%2.3f%%</td><td CLASS='serviceWARNING'>%2.3f%%</td></tr>\n", time_warning_string, percent_time_warning, percent_time_warning_known);

			/* unknown states */
			printf("<tr CLASS='dataEven'><td CLASS='serviceUNKNOWN' rowspan=3>未知</td>");
			printf("<td CLASS='dataEven'>未安排</td><td CLASS='dataEven'>%s</td><td CLASS='dataEven'>%2.3f%%</td><td CLASS='dataEven'>%2.3f%%</td></tr>\n", time_unknown_unscheduled_string, percent_time_unknown_unscheduled, percent_time_unknown_unscheduled_known);
			printf("<tr CLASS='dataEven'><td CLASS='dataEven'>安排</td><td CLASS='dataEven'>%s</td><td CLASS='dataEven'>%2.3f%%</td><td CLASS='dataEven'>%2.3f%%</td></tr>\n", time_unknown_scheduled_string, percent_time_unknown_scheduled, percent_time_unknown_scheduled_known);
			printf("<tr CLASS='serviceUNKNOWN'><td CLASS='serviceUNKNOWN'>总计</td><td CLASS='serviceUNKNOWN'>%s</td><td CLASS='serviceUNKNOWN'>%2.3f%%</td><td CLASS='serviceUNKNOWN'>%2.3f%%</td></tr>\n", time_unknown_string, percent_time_unknown, percent_time_unknown_known);

			/* critical states */
			printf("<tr CLASS='dataOdd'><td CLASS='serviceCRITICAL' rowspan=3>严重</td>");
			printf("<td CLASS='dataOdd'>未安排</td><td CLASS='dataOdd'>%s</td><td CLASS='dataOdd'>%2.3f%%</td><td CLASS='dataOdd'>%2.3f%%</td></tr>\n", time_critical_unscheduled_string, percent_time_critical_unscheduled, percent_time_critical_unscheduled_known);
			printf("<tr CLASS='dataOdd'><td CLASS='dataOdd'>安排</td><td CLASS='dataOdd'>%s</td><td CLASS='dataOdd'>%2.3f%%</td><td CLASS='dataOdd'>%2.3f%%</td></tr>\n", time_critical_scheduled_string, percent_time_critical_scheduled, percent_time_critical_scheduled_known);
			printf("<tr CLASS='serviceCRITICAL'><td CLASS='serviceCRITICAL'>总计</td><td CLASS='serviceCRITICAL'>%s</td><td CLASS='serviceCRITICAL'>%2.3f%%</td><td CLASS='serviceCRITICAL'>%2.3f%%</td></tr>\n", time_critical_string, percent_time_critical, percent_time_critical_known);


			printf("<tr CLASS='dataEven'><td CLASS='dataEven' rowspan=3>未决</td>");
			/*
			printf("<td CLASS='dataEven'>未安排</td><td CLASS='dataEven'>%s</td><td CLASS='dataEven'>%2.3f%%</td><td CLASS='dataEven'></td></tr>\n",time_indeterminate_unscheduled_string,percent_time_indeterminate_unscheduled);
			printf("<tr CLASS='dataEven'><td CLASS='dataEven'>安排</td><td CLASS='dataEven'>%s</td><td CLASS='dataEven'>%2.3f%%</td><td CLASS='dataEven'></td></tr>\n",time_indeterminate_scheduled_string,percent_time_indeterminate_scheduled);
			*/
			printf("<td CLASS='dataEven'>%s 未运行</td><td CLASS='dataEven'>%s</td><td CLASS='dataEven'>%2.3f%%</td><td CLASS='dataEven'></td></tr>\n", PROGRAM_VERSION, time_indeterminate_notrunning_string, percent_time_indeterminate_notrunning);
			printf("<tr CLASS='dataEven'><td CLASS='dataEven'>数据不足</td><td CLASS='dataEven'>%s</td><td CLASS='dataEven'>%2.3f%%</td><td CLASS='dataEven'></td></tr>\n", time_indeterminate_nodata_string, percent_time_indeterminate_nodata);
			printf("<tr CLASS='dataEven'><td CLASS='dataEven'>总计</td><td CLASS='dataEven'>%s</td><td CLASS='dataEven'>%2.3f%%</td><td CLASS='dataEven'></td></tr>\n", time_indeterminate_string, percent_time_indeterminate);

			printf("<tr><td colspan=3></td></tr>\n");
			printf("<tr CLASS='dataOdd'><td CLASS='dataOdd'>所有</td><td CLASS='dataOdd'>总计</td><td CLASS='dataOdd'>%s</td><td CLASS='dataOdd'>100.000%%</td><td CLASS='dataOdd'>100.000%%</td></tr>\n", total_time_string);
			printf("</table>\n");

		} else if (content_type == JSON_CONTENT) {
			printf("\"service_availability\": {\n");
			printf("\"services\": [\n");

			temp_host = find_host(temp_subject->host_name);

			/* host name and service description */
			printf("{ \"%s\": \"%s\", ", sheader[0], json_encode(temp_subject->host_name));
			printf(" \"%s\": \"%s\", ", sheader[47], (temp_host != NULL && temp_host->display_name != NULL) ? json_encode(temp_host->display_name) : json_encode(temp_host->name));
			printf(" \"%s\": \"%s\", ", sheader[1], json_encode(temp_subject->service_description));
			printf(" \"%s\": \"%s\", ", sheader[48], (temp_service->display_name != NULL) ? json_encode(temp_service->display_name) : json_encode(temp_service->description));

			/* ok times */
			printf(" \"%s\": %lu, ", sheader[2], temp_subject->scheduled_time_ok);
			printf(" \"%s\": %2.3f, ", sheader[3], percent_time_ok_scheduled);
			printf(" \"%s\": %2.3f, ", sheader[4], percent_time_ok_scheduled_known);
			printf(" \"%s\": %lu, ", sheader[5], temp_subject->time_ok - temp_subject->scheduled_time_ok);
			printf(" \"%s\": %2.3f, ", sheader[6], percent_time_ok_unscheduled);
			printf(" \"%s\": %2.3f, ", sheader[7], percent_time_ok_unscheduled_known);
			printf(" \"%s\": %lu, ", sheader[8], temp_subject->time_ok);
			printf(" \"%s\": %2.3f, ", sheader[9], percent_time_ok);
			printf(" \"%s\": %2.3f, ", sheader[10], percent_time_ok_known);

			/* warning times */
			printf(" \"%s\": %lu, ", sheader[11], temp_subject->scheduled_time_warning);
			printf(" \"%s\": %2.3f, ", sheader[12], percent_time_warning_scheduled);
			printf(" \"%s\": %2.3f, ", sheader[13], percent_time_warning_scheduled_known);
			printf(" \"%s\": %lu, ", sheader[14], temp_subject->time_warning - temp_subject->scheduled_time_warning);
			printf(" \"%s\": %2.3f, ", sheader[15], percent_time_warning_unscheduled);
			printf(" \"%s\": %2.3f, ", sheader[16], percent_time_warning_unscheduled_known);
			printf(" \"%s\": %lu, ", sheader[17], temp_subject->time_warning);
			printf(" \"%s\": %2.3f, ", sheader[18], percent_time_warning);
			printf(" \"%s\": %2.3f, ", sheader[19], percent_time_warning_known);

			/* unknown times */
			printf(" \"%s\": %lu, ", sheader[20], temp_subject->scheduled_time_unknown);
			printf(" \"%s\": %2.3f, ", sheader[21], percent_time_unknown_scheduled);
			printf(" \"%s\": %2.3f, ", sheader[22], percent_time_unknown_scheduled_known);
			printf(" \"%s\": %lu, ", sheader[23], temp_subject->time_unknown - temp_subject->scheduled_time_unknown);
			printf(" \"%s\": %2.3f, ", sheader[24], percent_time_unknown_unscheduled);
			printf(" \"%s\": %2.3f, ", sheader[25], percent_time_unknown_unscheduled_known);
			printf(" \"%s\": %lu, ", sheader[26], temp_subject->time_unknown);
			printf(" \"%s\": %2.3f, ", sheader[27], percent_time_unknown);
			printf(" \"%s\": %2.3f, ", sheader[28], percent_time_unknown_known);

			/* critical times */
			printf(" \"%s\": %lu, ", sheader[29], temp_subject->scheduled_time_critical);
			printf(" \"%s\": %2.3f, ", sheader[30], percent_time_critical_scheduled);
			printf(" \"%s\": %2.3f, ", sheader[31], percent_time_critical_scheduled_known);
			printf(" \"%s\": %lu, ", sheader[32], temp_subject->time_critical - temp_subject->scheduled_time_critical);
			printf(" \"%s\": %2.3f, ", sheader[33], percent_time_critical_unscheduled);
			printf(" \"%s\": %2.3f, ", sheader[34], percent_time_critical_unscheduled_known);
			printf(" \"%s\": %lu, ", sheader[35], temp_subject->time_critical);
			printf(" \"%s\": %2.3f, ", sheader[36], percent_time_critical);
			printf(" \"%s\": %2.3f, ", sheader[37], percent_time_critical_known);


			/* indeterminate times */
			printf(" \"%s\": %lu, ", sheader[38], temp_subject->time_indeterminate_notrunning);
			printf(" \"%s\": %2.3f, ", sheader[39], percent_time_indeterminate_notrunning);
			printf(" \"%s\": %lu, ", sheader[40], temp_subject->time_indeterminate_nodata);
			printf(" \"%s\": %2.3f, ", sheader[41], percent_time_indeterminate_nodata);
			printf(" \"%s\": %lu, ", sheader[42], time_indeterminate);
			printf(" \"%s\": %2.3f, ", sheader[43], percent_time_indeterminate);

			/* total times */
			printf(" \"%s\": %lu, ", sheader[44], total_time);
			printf(" \"%s\": 100.000, ", sheader[45]);
			printf(" \"%s\": 100.000,\n", sheader[46]);

		} else if (content_type == XML_CONTENT) {

			printf("<service_availability>\n");
			printf("<service name=\"%s\" host_name=\"%s\">\n", temp_subject->service_description, temp_subject->host_name);

			/* ok times */
			printf("<%s>%lu</%s>\n", sheader[2], temp_subject->scheduled_time_ok, sheader[2]);
			printf("<%s>%2.3f</%s>\n", sheader[3], percent_time_ok_scheduled, sheader[3]);
			printf("<%s>%2.3f</%s>\n", sheader[4], percent_time_ok_scheduled_known, sheader[4]);
			printf("<%s>%lu</%s>\n", sheader[5], temp_subject->time_ok - temp_subject->scheduled_time_ok, sheader[5]);
			printf("<%s>%2.3f</%s>\n", sheader[6], percent_time_ok_unscheduled, sheader[6]);
			printf("<%s>%2.3f</%s>\n", sheader[7], percent_time_ok_unscheduled_known, sheader[7]);
			printf("<%s>%lu</%s>\n", sheader[8], temp_subject->time_ok, sheader[8]);
			printf("<%s>%2.3f</%s>\n", sheader[9], percent_time_ok, sheader[9]);
			printf("<%s>%2.3f</%s>\n", sheader[10], percent_time_ok_known, sheader[10]);

			/* warning times */
			printf("<%s>%lu</%s>\n", sheader[11], temp_subject->scheduled_time_warning, sheader[11]);
			printf("<%s>%2.3f</%s>\n", sheader[12], percent_time_warning_scheduled, sheader[12]);
			printf("<%s>%2.3f</%s>\n", sheader[13], percent_time_warning_scheduled_known, sheader[13]);
			printf("<%s>%lu</%s>\n", sheader[14], temp_subject->time_warning - temp_subject->scheduled_time_warning, sheader[14]);
			printf("<%s>%2.3f</%s>\n", sheader[15], percent_time_warning_unscheduled, sheader[15]);
			printf("<%s>%2.3f</%s>\n", sheader[16], percent_time_warning_unscheduled_known, sheader[16]);
			printf("<%s>%lu</%s>\n", sheader[17], temp_subject->time_warning, sheader[17]);
			printf("<%s>%2.3f</%s>\n", sheader[18], percent_time_warning, sheader[18]);
			printf("<%s>%2.3f</%s>\n", sheader[19], percent_time_warning_known, sheader[19]);

			/* unknown times */
			printf("<%s>%lu</%s>\n", sheader[20], temp_subject->scheduled_time_unknown, sheader[20]);
			printf("<%s>%2.3f</%s>\n", sheader[21], percent_time_unknown_scheduled, sheader[21]);
			printf("<%s>%2.3f</%s>\n", sheader[22], percent_time_unknown_scheduled_known, sheader[22]);
			printf("<%s>%lu</%s>\n", sheader[23], temp_subject->time_unknown - temp_subject->scheduled_time_unknown, sheader[23]);
			printf("<%s>%2.3f</%s>\n", sheader[24], percent_time_unknown_unscheduled, sheader[24]);
			printf("<%s>%2.3f</%s>\n", sheader[25], percent_time_unknown_unscheduled_known, sheader[25]);
			printf("<%s>%lu</%s>\n", sheader[26], temp_subject->time_unknown, sheader[26]);
			printf("<%s>%2.3f</%s>\n", sheader[27], percent_time_unknown, sheader[27]);
			printf("<%s>%2.3f</%s>\n", sheader[28], percent_time_unknown_known, sheader[28]);

			/* critical times */
			printf("<%s>%lu</%s>\n", sheader[29], temp_subject->scheduled_time_critical, sheader[29]);
			printf("<%s>%2.3f</%s>\n", sheader[30], percent_time_critical_scheduled, sheader[30]);
			printf("<%s>%2.3f</%s>\n", sheader[31], percent_time_critical_scheduled_known, sheader[31]);
			printf("<%s>%lu</%s>\n", sheader[32], temp_subject->time_critical - temp_subject->scheduled_time_critical, sheader[32]);
			printf("<%s>%2.3f</%s>\n", sheader[33], percent_time_critical_unscheduled, sheader[33]);
			printf("<%s>%2.3f</%s>\n", sheader[34], percent_time_critical_unscheduled_known, sheader[34]);
			printf("<%s>%lu</%s>\n", sheader[35], temp_subject->time_critical, sheader[35]);
			printf("<%s>%2.3f</%s>\n", sheader[36], percent_time_critical, sheader[36]);
			printf("<%s>%2.3f</%s>\n", sheader[37], percent_time_critical_known, sheader[37]);


			/* indeterminate times */
			printf("<%s>%lu</%s>\n", sheader[38], temp_subject->time_indeterminate_notrunning, sheader[38]);
			printf("<%s>%2.3f</%s>\n", sheader[39], percent_time_indeterminate_notrunning, sheader[39]);
			printf("<%s>%lu</%s>\n", sheader[40], temp_subject->time_indeterminate_nodata, sheader[40]);
			printf("<%s>%2.3f</%s>\n", sheader[41], percent_time_indeterminate_nodata, sheader[41]);
			printf("<%s>%lu</%s>\n", sheader[42], time_indeterminate, sheader[42]);
			printf("<%s>%2.3f</%s>\n", sheader[43], percent_time_indeterminate, sheader[43]);

			/* total times */
			printf("<%s>%lu</%s>\n", sheader[44], total_time, sheader[44]);
			printf("<%s>100.000</%s>\n", sheader[45], sheader[45]);
			printf("<%s>100.000</%s>\n", sheader[46], sheader[46]);

		} else if (content_type == CSV_CONTENT) {

			for (i = 0; i < sheader_num -2; i++)
				printf("%s%s%s%s", csv_data_enclosure, sheader[i], csv_data_enclosure, csv_delimiter);

			printf("\n");

			/* host name and service description */
			printf("%s%s%s%s", csv_data_enclosure, temp_subject->host_name, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, temp_subject->service_description, csv_data_enclosure, csv_delimiter);

			/* ok times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_ok, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok_scheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok_scheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_ok - temp_subject->scheduled_time_ok, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok_unscheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok_unscheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_ok, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok_known, csv_data_enclosure, csv_delimiter);

			/* warning times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_warning, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning_scheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning_scheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_warning - temp_subject->scheduled_time_warning, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning_unscheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning_unscheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_warning, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning_known, csv_data_enclosure, csv_delimiter);

			/* unknown times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_unknown, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown_scheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown_scheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_unknown - temp_subject->scheduled_time_unknown, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown_unscheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown_unscheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_unknown, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown_known, csv_data_enclosure, csv_delimiter);

			/* critical times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_critical, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical_scheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical_scheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_critical - temp_subject->scheduled_time_critical, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical_unscheduled, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical_unscheduled_known, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_critical, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical_known, csv_data_enclosure, csv_delimiter);

			/* indeterminate times */
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_indeterminate_notrunning, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate_notrunning, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_indeterminate_nodata, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate_nodata, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s",    csv_data_enclosure, time_indeterminate, csv_data_enclosure, csv_delimiter);
			printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate, csv_data_enclosure, csv_delimiter);

			/* total times */
			printf("%s%lu%s%s", csv_data_enclosure, total_time, csv_data_enclosure, csv_delimiter);
			printf("%s100.000%%%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s100.000%%%s", csv_data_enclosure, csv_data_enclosure);

			printf("\n");

		}

		write_log_entries(temp_subject);

		if (content_type == XML_CONTENT) {
			printf("</service>\n");
			printf("</service_availability>\n");
		} else if (content_type == JSON_CONTENT)
			printf("\n}\n]\n}\n");
	}


	/* display data for all services */
	else {

		if (content_type == HTML_CONTENT) {

			printf("<DIV ALIGN=CENTER CLASS='dataTitle'>服务状态细分:</DIV>\n");

			printf("<TABLE BORDER=0 CLASS='data' align='center'>\n");
			printf("<TR><TH CLASS='data'>主机</TH><TH CLASS='data'>服务</TH><TH CLASS='data'>%% 正常时间</TH><TH CLASS='data'>%% 警报时间</TH><TH CLASS='data'>%% 未知时</TH><TH CLASS='data'>%% 严重时间</TH><TH CLASS='data'>%% 未决时间</TH></TR>\n");

		} else if (content_type == JSON_CONTENT) {
			printf("\"服务可用性\": {\n");
			printf("\"服务\": [\n");
		} else if (content_type == XML_CONTENT) {
			printf("<service_availability>\n");
		} else if (content_type == CSV_CONTENT) {

			for (i = 0; i < sheader_num -2; i++)
				printf("%s%s%s%s", csv_data_enclosure, sheader[i], csv_data_enclosure, csv_delimiter);

			printf("\n");
		}


		for (temp_subject = subject_list; temp_subject != NULL; temp_subject = temp_subject->next) {

			if (temp_subject->type != SERVICE_SUBJECT)
				continue;

			temp_service = find_service(temp_subject->host_name, temp_subject->service_description);
			if (temp_service == NULL)
				continue;

			/* the user isn't authorized to view this service */
			if (is_authorized_for_service(temp_service, &current_authdata) == FALSE)
				continue;

			current_subject++;

			time_determinate = temp_subject->time_ok + temp_subject->time_warning + temp_subject->time_unknown + temp_subject->time_critical;
			time_indeterminate = total_time - time_determinate;

			/* adjust indeterminate time due to insufficient data (not all was caught) */
			temp_subject->time_indeterminate_nodata = time_indeterminate - temp_subject->time_indeterminate_notrunning;

			/* initialize values */
			percent_time_ok = 0.0;
			percent_time_ok_scheduled = 0.0;
			percent_time_ok_unscheduled = 0.0;
			percent_time_warning = 0.0;
			percent_time_warning_scheduled = 0.0;
			percent_time_warning_unscheduled = 0.0;
			percent_time_unknown = 0.0;
			percent_time_unknown_scheduled = 0.0;
			percent_time_unknown_unscheduled = 0.0;
			percent_time_critical = 0.0;
			percent_time_critical_scheduled = 0.0;
			percent_time_critical_unscheduled = 0.0;
			percent_time_indeterminate = 0.0;
			percent_time_indeterminate_scheduled = 0.0;
			percent_time_indeterminate_unscheduled = 0.0;
			percent_time_indeterminate_notrunning = 0.0;
			percent_time_indeterminate_nodata = 0.0;
			percent_time_ok_known = 0.0;
			percent_time_ok_scheduled_known = 0.0;
			percent_time_ok_unscheduled_known = 0.0;
			percent_time_warning_known = 0.0;
			percent_time_warning_scheduled_known = 0.0;
			percent_time_warning_unscheduled_known = 0.0;
			percent_time_unknown_known = 0.0;
			percent_time_unknown_scheduled_known = 0.0;
			percent_time_unknown_unscheduled_known = 0.0;
			percent_time_critical_known = 0.0;
			percent_time_critical_scheduled_known = 0.0;
			percent_time_critical_unscheduled_known = 0.0;

			if (total_time > 0) {
				percent_time_ok = (double)(((double)temp_subject->time_ok * 100.0) / (double)total_time);
				percent_time_ok_scheduled = (double)(((double)temp_subject->scheduled_time_ok * 100.0) / (double)total_time);
				percent_time_ok_unscheduled = percent_time_ok - percent_time_ok_scheduled;
				percent_time_warning = (double)(((double)temp_subject->time_warning * 100.0) / (double)total_time);
				percent_time_warning_scheduled = (double)(((double)temp_subject->scheduled_time_unknown * 100.0) / (double)total_time);
				percent_time_warning_unscheduled = percent_time_warning - percent_time_warning_scheduled;
				percent_time_unknown = (double)(((double)temp_subject->time_unknown * 100.0) / (double)total_time);
				percent_time_unknown_scheduled = (double)(((double)temp_subject->scheduled_time_unknown * 100.0) / (double)total_time);
				percent_time_unknown_unscheduled = percent_time_unknown - percent_time_unknown_scheduled;
				percent_time_critical = (double)(((double)temp_subject->time_critical * 100.0) / (double)total_time);
				percent_time_critical_scheduled = (double)(((double)temp_subject->scheduled_time_critical * 100.0) / (double)total_time);
				percent_time_critical_unscheduled = percent_time_critical - percent_time_critical_scheduled;
				percent_time_indeterminate = (double)(((double)time_indeterminate * 100.0) / (double)total_time);
				percent_time_indeterminate_scheduled = (double)(((double)temp_subject->scheduled_time_indeterminate * 100.0) / (double)total_time);
				percent_time_indeterminate_unscheduled = percent_time_indeterminate - percent_time_indeterminate_scheduled;
				percent_time_indeterminate_notrunning = (double)(((double)temp_subject->time_indeterminate_notrunning * 100.0) / (double)total_time);
				percent_time_indeterminate_nodata = (double)(((double)temp_subject->time_indeterminate_nodata * 100.0) / (double)total_time);
				if (time_determinate > 0) {
					percent_time_ok_known = (double)(((double)temp_subject->time_ok * 100.0) / (double)time_determinate);
					percent_time_ok_scheduled_known = (double)(((double)temp_subject->scheduled_time_ok * 100.0) / (double)time_determinate);
					percent_time_ok_unscheduled_known = percent_time_ok_known - percent_time_ok_scheduled_known;
					percent_time_warning_known = (double)(((double)temp_subject->time_warning * 100.0) / (double)time_determinate);
					percent_time_warning_scheduled_known = (double)(((double)temp_subject->scheduled_time_warning * 100.0) / (double)time_determinate);
					percent_time_warning_unscheduled_known = percent_time_warning_known - percent_time_warning_scheduled_known;
					percent_time_unknown_known = (double)(((double)temp_subject->time_unknown * 100.0) / (double)time_determinate);
					percent_time_unknown_scheduled_known = (double)(((double)temp_subject->scheduled_time_unknown * 100.0) / (double)time_determinate);
					percent_time_unknown_unscheduled_known = percent_time_unknown_known - percent_time_unknown_scheduled_known;
					percent_time_critical_known = (double)(((double)temp_subject->time_critical * 100.0) / (double)time_determinate);
					percent_time_critical_scheduled_known = (double)(((double)temp_subject->scheduled_time_critical * 100.0) / (double)time_determinate);
					percent_time_critical_unscheduled_known = percent_time_critical_known - percent_time_critical_scheduled_known;
				}
			}

			if (content_type == HTML_CONTENT) {

				if (odd) {
					odd = 0;
					bgclass = "Odd";
				} else {
					odd = 1;
					bgclass = "Even";
				}

				printf("<tr CLASS='data%s'><td CLASS='data%s'>", bgclass, bgclass);
				if (strcmp(temp_subject->host_name, last_host))
					host_report_url(temp_subject->host_name, temp_subject->host_name);
				printf("</td><td CLASS='data%s'>", bgclass);
				service_report_url(temp_subject->host_name, temp_subject->service_description, temp_subject->service_description);
				printf("</td><td CLASS='serviceOK'>%2.3f%% (%2.3f%%)</td><td CLASS='serviceWARNING'>%2.3f%% (%2.3f%%)</td><td CLASS='serviceUNKNOWN'>%2.3f%% (%2.3f%%)</td><td class='serviceCRITICAL'>%2.3f%% (%2.3f%%)</td><td class='data%s' align='center'>%2.3f%%</td></tr>\n", percent_time_ok, percent_time_ok_known, percent_time_warning, percent_time_warning_known, percent_time_unknown, percent_time_unknown_known, percent_time_critical, percent_time_critical_known, bgclass, percent_time_indeterminate);

			} else if (content_type == JSON_CONTENT) {
				if (json_start != TRUE)
					printf(",\n");

				temp_host = find_host(temp_subject->host_name);

				/* host name and service description */
				printf("{ \"%s\": \"%s\", ", sheader[0], json_encode(temp_subject->host_name));
				printf(" \"%s\": \"%s\", ", sheader[47], (temp_host != NULL && temp_host->display_name != NULL) ? json_encode(temp_host->display_name) : json_encode(temp_host->name));
				printf(" \"%s\": \"%s\", ", sheader[1], json_encode(temp_subject->service_description));
				printf(" \"%s\": \"%s\", ", sheader[48], (temp_service->display_name != NULL) ? json_encode(temp_service->display_name) : json_encode(temp_service->description));

				/* ok times */
				printf(" \"%s\": %lu, ", sheader[2], temp_subject->scheduled_time_ok);
				printf(" \"%s\": %2.3f, ", sheader[3], percent_time_ok_scheduled);
				printf(" \"%s\": %2.3f, ", sheader[4], percent_time_ok_scheduled_known);
				printf(" \"%s\": %lu, ", sheader[5], temp_subject->time_ok - temp_subject->scheduled_time_ok);
				printf(" \"%s\": %2.3f, ", sheader[6], percent_time_ok_unscheduled);
				printf(" \"%s\": %2.3f, ", sheader[7], percent_time_ok_unscheduled_known);
				printf(" \"%s\": %lu, ", sheader[8], temp_subject->time_ok);
				printf(" \"%s\": %2.3f, ", sheader[9], percent_time_ok);
				printf(" \"%s\": %2.3f, ", sheader[10], percent_time_ok_known);

				/* warning times */
				printf(" \"%s\": %lu, ", sheader[11], temp_subject->scheduled_time_warning);
				printf(" \"%s\": %2.3f, ", sheader[12], percent_time_warning_scheduled);
				printf(" \"%s\": %2.3f, ", sheader[13], percent_time_warning_scheduled_known);
				printf(" \"%s\": %lu, ", sheader[14], temp_subject->time_warning - temp_subject->scheduled_time_warning);
				printf(" \"%s\": %2.3f, ", sheader[15], percent_time_warning_unscheduled);
				printf(" \"%s\": %2.3f, ", sheader[16], percent_time_warning_unscheduled_known);
				printf(" \"%s\": %lu, ", sheader[17], temp_subject->time_warning);
				printf(" \"%s\": %2.3f, ", sheader[18], percent_time_warning);
				printf(" \"%s\": %2.3f, ", sheader[19], percent_time_warning_known);

				/* unknown times */
				printf(" \"%s\": %lu, ", sheader[20], temp_subject->scheduled_time_unknown);
				printf(" \"%s\": %2.3f, ", sheader[21], percent_time_unknown_scheduled);
				printf(" \"%s\": %2.3f, ", sheader[22], percent_time_unknown_scheduled_known);
				printf(" \"%s\": %lu, ", sheader[23], temp_subject->time_unknown - temp_subject->scheduled_time_unknown);
				printf(" \"%s\": %2.3f, ", sheader[24], percent_time_unknown_unscheduled);
				printf(" \"%s\": %2.3f, ", sheader[25], percent_time_unknown_unscheduled_known);
				printf(" \"%s\": %lu, ", sheader[26], temp_subject->time_unknown);
				printf(" \"%s\": %2.3f, ", sheader[27], percent_time_unknown);
				printf(" \"%s\": %2.3f, ", sheader[28], percent_time_unknown_known);

				/* critical times */
				printf(" \"%s\": %lu, ", sheader[29], temp_subject->scheduled_time_critical);
				printf(" \"%s\": %2.3f, ", sheader[30], percent_time_critical_scheduled);
				printf(" \"%s\": %2.3f, ", sheader[31], percent_time_critical_scheduled_known);
				printf(" \"%s\": %lu, ", sheader[32], temp_subject->time_critical - temp_subject->scheduled_time_critical);
				printf(" \"%s\": %2.3f, ", sheader[33], percent_time_critical_unscheduled);
				printf(" \"%s\": %2.3f, ", sheader[34], percent_time_critical_unscheduled_known);
				printf(" \"%s\": %lu, ", sheader[35], temp_subject->time_critical);
				printf(" \"%s\": %2.3f, ", sheader[36], percent_time_critical);
				printf(" \"%s\": %2.3f, ", sheader[37], percent_time_critical_known);


				/* indeterminate times */
				printf(" \"%s\": %lu, ", sheader[38], temp_subject->time_indeterminate_notrunning);
				printf(" \"%s\": %2.3f, ", sheader[39], percent_time_indeterminate_notrunning);
				printf(" \"%s\": %lu, ", sheader[40], temp_subject->time_indeterminate_nodata);
				printf(" \"%s\": %2.3f, ", sheader[41], percent_time_indeterminate_nodata);
				printf(" \"%s\": %lu, ", sheader[42], time_indeterminate);
				printf(" \"%s\": %2.3f, ", sheader[43], percent_time_indeterminate);

				/* total times */
				printf(" \"%s\": %lu, ", sheader[44], total_time);
				printf(" \"%s\": 100.000, ", sheader[45]);
				printf(" \"%s\": 100.000} ", sheader[46]);

				json_start = FALSE;

			} else if (content_type == XML_CONTENT) {

				printf("<service name=\"%s\" host_name=\"%s\">\n", temp_subject->service_description, temp_subject->host_name);

				/* ok times */
				printf("<%s>%lu</%s>\n", sheader[2], temp_subject->scheduled_time_ok, sheader[2]);
				printf("<%s>%2.3f</%s>\n", sheader[3], percent_time_ok_scheduled, sheader[3]);
				printf("<%s>%2.3f</%s>\n", sheader[4], percent_time_ok_scheduled_known, sheader[4]);
				printf("<%s>%lu</%s>\n", sheader[5], temp_subject->time_ok - temp_subject->scheduled_time_ok, sheader[5]);
				printf("<%s>%2.3f</%s>\n", sheader[6], percent_time_ok_unscheduled, sheader[6]);
				printf("<%s>%2.3f</%s>\n", sheader[7], percent_time_ok_unscheduled_known, sheader[7]);
				printf("<%s>%lu</%s>\n", sheader[8], temp_subject->time_ok, sheader[8]);
				printf("<%s>%2.3f</%s>\n", sheader[9], percent_time_ok, sheader[9]);
				printf("<%s>%2.3f</%s>\n", sheader[10], percent_time_ok_known, sheader[10]);

				/* warning times */
				printf("<%s>%lu</%s>\n", sheader[11], temp_subject->scheduled_time_warning, sheader[11]);
				printf("<%s>%2.3f</%s>\n", sheader[12], percent_time_warning_scheduled, sheader[12]);
				printf("<%s>%2.3f</%s>\n", sheader[13], percent_time_warning_scheduled_known, sheader[13]);
				printf("<%s>%lu</%s>\n", sheader[14], temp_subject->time_warning - temp_subject->scheduled_time_warning, sheader[14]);
				printf("<%s>%2.3f</%s>\n", sheader[15], percent_time_warning_unscheduled, sheader[15]);
				printf("<%s>%2.3f</%s>\n", sheader[16], percent_time_warning_unscheduled_known, sheader[16]);
				printf("<%s>%lu</%s>\n", sheader[17], temp_subject->time_warning, sheader[17]);
				printf("<%s>%2.3f</%s>\n", sheader[18], percent_time_warning, sheader[18]);
				printf("<%s>%2.3f</%s>\n", sheader[19], percent_time_warning_known, sheader[19]);

				/* unknown times */
				printf("<%s>%lu</%s>\n", sheader[20], temp_subject->scheduled_time_unknown, sheader[20]);
				printf("<%s>%2.3f</%s>\n", sheader[21], percent_time_unknown_scheduled, sheader[21]);
				printf("<%s>%2.3f</%s>\n", sheader[22], percent_time_unknown_scheduled_known, sheader[22]);
				printf("<%s>%lu</%s>\n", sheader[23], temp_subject->time_unknown - temp_subject->scheduled_time_unknown, sheader[23]);
				printf("<%s>%2.3f</%s>\n", sheader[24], percent_time_unknown_unscheduled, sheader[24]);
				printf("<%s>%2.3f</%s>\n", sheader[25], percent_time_unknown_unscheduled_known, sheader[25]);
				printf("<%s>%lu</%s>\n", sheader[26], temp_subject->time_unknown, sheader[26]);
				printf("<%s>%2.3f</%s>\n", sheader[27], percent_time_unknown, sheader[27]);
				printf("<%s>%2.3f</%s>\n", sheader[28], percent_time_unknown_known, sheader[28]);

				/* critical times */
				printf("<%s>%lu</%s>\n", sheader[29], temp_subject->scheduled_time_critical, sheader[29]);
				printf("<%s>%2.3f</%s>\n", sheader[30], percent_time_critical_scheduled, sheader[30]);
				printf("<%s>%2.3f</%s>\n", sheader[31], percent_time_critical_scheduled_known, sheader[31]);
				printf("<%s>%lu</%s>\n", sheader[32], temp_subject->time_critical - temp_subject->scheduled_time_critical, sheader[32]);
				printf("<%s>%2.3f</%s>\n", sheader[33], percent_time_critical_unscheduled, sheader[33]);
				printf("<%s>%2.3f</%s>\n", sheader[34], percent_time_critical_unscheduled_known, sheader[34]);
				printf("<%s>%lu</%s>\n", sheader[35], temp_subject->time_critical, sheader[35]);
				printf("<%s>%2.3f</%s>\n", sheader[36], percent_time_critical, sheader[36]);
				printf("<%s>%2.3f</%s>\n", sheader[37], percent_time_critical_known, sheader[37]);


				/* indeterminate times */
				printf("<%s>%lu</%s>\n", sheader[38], temp_subject->time_indeterminate_notrunning, sheader[38]);
				printf("<%s>%2.3f</%s>\n", sheader[39], percent_time_indeterminate_notrunning, sheader[39]);
				printf("<%s>%lu</%s>\n", sheader[40], temp_subject->time_indeterminate_nodata, sheader[40]);
				printf("<%s>%2.3f</%s>\n", sheader[41], percent_time_indeterminate_nodata, sheader[41]);
				printf("<%s>%lu</%s>\n", sheader[42], time_indeterminate, sheader[42]);
				printf("<%s>%2.3f</%s>\n", sheader[43], percent_time_indeterminate, sheader[43]);

				/* total times */
				printf("<%s>%lu</%s>\n", sheader[44], total_time, sheader[44]);
				printf("<%s>100.000</%s>\n", sheader[45], sheader[45]);
				printf("<%s>100.000</%s>\n", sheader[46], sheader[46]);

				printf("</service>\n");

			} else if (content_type == CSV_CONTENT) {
				/* host name and service description */
				printf("%s%s%s%s", csv_data_enclosure, temp_subject->host_name, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, temp_subject->service_description, csv_data_enclosure, csv_delimiter);

				/* ok times */
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_ok, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok_scheduled, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok_scheduled_known, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_ok - temp_subject->scheduled_time_ok, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok_unscheduled, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok_unscheduled_known, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_ok, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_ok_known, csv_data_enclosure, csv_delimiter);

				/* warning times */
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_warning, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning_scheduled, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning_scheduled_known, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_warning - temp_subject->scheduled_time_warning, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning_unscheduled, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning_unscheduled_known, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_warning, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_warning_known, csv_data_enclosure, csv_delimiter);

				/* unknown times */
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_unknown, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown_scheduled, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown_scheduled_known, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_unknown - temp_subject->scheduled_time_unknown, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown_unscheduled, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown_unscheduled_known, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_unknown, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_unknown_known, csv_data_enclosure, csv_delimiter);

				/* critical times */
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->scheduled_time_critical, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical_scheduled, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical_scheduled_known, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_critical - temp_subject->scheduled_time_critical, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical_unscheduled, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical_unscheduled_known, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_critical, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_critical_known, csv_data_enclosure, csv_delimiter);

				/* indeterminate times */
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_indeterminate_notrunning, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate_notrunning, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, temp_subject->time_indeterminate_nodata, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate_nodata, csv_data_enclosure, csv_delimiter);
				printf("%s%lu%s%s",    csv_data_enclosure, time_indeterminate, csv_data_enclosure, csv_delimiter);
				printf("%s%2.3f%%%s%s", csv_data_enclosure, percent_time_indeterminate, csv_data_enclosure, csv_delimiter);

				/* total times */
				printf("%s%lu%s%s", csv_data_enclosure, total_time, csv_data_enclosure, csv_delimiter);
				printf("%s100.000%%%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
				printf("%s100.000%%%s", csv_data_enclosure, csv_data_enclosure);

				printf("\n");
			}

			strncpy(last_host, temp_subject->host_name, sizeof(last_host) - 1);
			last_host[sizeof(last_host)-1] = '\x0';

			get_running_average(&average_percent_time_ok, percent_time_ok, current_subject);
			get_running_average(&average_percent_time_ok_known, percent_time_ok_known, current_subject);
			get_running_average(&average_percent_time_unknown, percent_time_unknown, current_subject);
			get_running_average(&average_percent_time_unknown_known, percent_time_unknown_known, current_subject);
			get_running_average(&average_percent_time_warning, percent_time_warning, current_subject);
			get_running_average(&average_percent_time_warning_known, percent_time_warning_known, current_subject);
			get_running_average(&average_percent_time_critical, percent_time_critical, current_subject);
			get_running_average(&average_percent_time_critical_known, percent_time_critical_known, current_subject);
			get_running_average(&average_percent_time_indeterminate, percent_time_indeterminate, current_subject);
		}

		if (content_type == HTML_CONTENT) {

			/* average statistics */
			if (odd) {
				odd = 0;
				bgclass = "Odd";
			} else {
				odd = 1;
				bgclass = "Even";
			}
			printf("<tr CLASS='data%s'><td CLASS='data%s' colspan='2'>平均</td><td CLASS='serviceOK'>%2.3f%% (%2.3f%%)</td><td CLASS='serviceWARNING'>%2.3f%% (%2.3f%%)</td><td CLASS='serviceUNKNOWN'>%2.3f%% (%2.3f%%)</td><td class='serviceCRITICAL'>%2.3f%% (%2.3f%%)</td><td class='data%s' align='center'>%2.3f%%</td></tr>\n", bgclass, bgclass, average_percent_time_ok, average_percent_time_ok_known, average_percent_time_warning, average_percent_time_warning_known, average_percent_time_unknown, average_percent_time_unknown_known, average_percent_time_critical, average_percent_time_critical_known, bgclass, average_percent_time_indeterminate);
			printf("</table>\n");
		} else if (content_type == XML_CONTENT) {
			printf("<all_services_average>\n");
			printf("<average_percent_time_ok>%2.3f</average_percent_time_ok>\n", average_percent_time_ok);
			printf("<average_percent_time_ok_known>%2.3f</average_percent_time_ok_known>\n", average_percent_time_ok_known);
			printf("<average_percent_time_warning>%2.3f</average_percent_time_warning>\n", average_percent_time_warning);
			printf("<average_percent_time_warning_known>%2.3f</average_percent_time_warning_known>\n", average_percent_time_warning_known);
			printf("<average_percent_time_unknown>%2.3f</average_percent_time_unknown>\n", average_percent_time_unknown);
			printf("<average_percent_time_unknown_known>%2.3f</average_percent_time_unknown_known>\n", average_percent_time_unknown_known);
			printf("<average_percent_time_critical>%2.3f</average_percent_time_critical>\n", average_percent_time_critical);
			printf("<average_percent_time_critical_known>%2.3f</average_percent_time_critical_known>\n", average_percent_time_critical_known);
			printf("<average_percent_time_indeterminate>%2.3f</average_percent_time_indeterminate>\n", average_percent_time_indeterminate);
			printf("</all_services_average>\n");
			printf("</service_availability>\n");
		} else if (content_type == JSON_CONTENT) {
			printf(" ],\n");
			printf("\"所有服务平均值\": [ {");
			printf("\"正常时间平均百分比\": %2.3f, ", average_percent_time_ok);
			printf("\"已知正常时间平均百分比\": %2.3f, ", average_percent_time_ok_known);
			printf("\"警报时间平均百分比\": %2.3f, ", average_percent_time_warning);
			printf("\"已知警报时间平均百分比\": %2.3f, ", average_percent_time_warning_known);
			printf("\"未知时间平均百分比\": %2.3f, ", average_percent_time_unknown);
			printf("\"已知未知时间平均百分比\": %2.3f, ", average_percent_time_unknown_known);
			printf("\"严重时间平均百分比\": %2.3f, ", average_percent_time_critical);
			printf("\"已知严重时间平均百分比\": %2.3f, ", average_percent_time_critical_known);
			printf("\"未决时间平均百分比\": %2.3f } ] }\n", average_percent_time_indeterminate);
		} else if (content_type == CSV_CONTENT) {
			/* average */
			/* left for future rework */
		}

	}

	return;
}



void host_report_url(char *hn, char *label) {

	printf("<a href='%s?host=%s", AVAIL_CGI, url_encode(hn));
	printf("&show_log_entries");
	printf("&t1=%lu&t2=%lu", t1, t2);
	printf("&backtrack=%d", backtrack_archives);
	printf("&assumestateretention=%s", (assume_state_retention == TRUE) ? "yes" : "no");
	printf("&assumeinitialstates=%s", (assume_initial_states == TRUE) ? "yes" : "no");
	printf("&assumestatesduringnotrunning=%s", (assume_states_during_notrunning == TRUE) ? "yes" : "no");
	printf("&initialassumedhoststate=%d", initial_assumed_host_state);
	printf("&initialassumedservicestate=%d", initial_assumed_service_state);
	if (show_log_entries == TRUE)
		printf("&show_log_entries");
	if (full_log_entries == TRUE)
		printf("&full_log_entries");
	printf("&showscheduleddowntime=%s", (show_scheduled_downtime == TRUE) ? "yes" : "no");
	if (current_timeperiod != NULL)
		printf("&rpttimeperiod=%s", url_encode(current_timeperiod->name));
	printf("'>%s</a>", label);

	return;
}


void service_report_url(char *hn, char *sd, char *label) {

	printf("<a href='%s?host=%s", AVAIL_CGI, url_encode(hn));
	printf("&service=%s", url_encode(sd));
	printf("&t1=%lu&t2=%lu", t1, t2);
	printf("&backtrack=%d", backtrack_archives);
	printf("&assumestateretention=%s", (assume_state_retention == TRUE) ? "yes" : "no");
	printf("&assumeinitialstates=%s", (assume_initial_states == TRUE) ? "yes" : "no");
	printf("&assumestatesduringnotrunning=%s", (assume_states_during_notrunning == TRUE) ? "yes" : "no");
	printf("&initialassumedhoststate=%d", initial_assumed_host_state);
	printf("&initialassumedservicestate=%d", initial_assumed_service_state);
	if (show_log_entries == TRUE)
		printf("&show_log_entries");
	if (full_log_entries == TRUE)
		printf("&full_log_entries");
	printf("&showscheduleddowntime=%s", (show_scheduled_downtime == TRUE) ? "yes" : "no");
	if (current_timeperiod != NULL)
		printf("&rpttimeperiod=%s", url_encode(current_timeperiod->name));
	printf("'>%s</a>", label);

	return;
}


/* calculates running average */
void get_running_average(double *running_average, double new_value, int current_item) {

	*running_average = (((*running_average * ((double)current_item - 1.0)) + new_value) / (double)current_item);

	return;
}


/* used in reports where a timeperiod is selected */
unsigned long calculate_total_time(time_t start_time, time_t end_time) {
	struct tm *t;
	unsigned long midnight_today;
	int weekday;
	unsigned long total_time;
	timerange *temp_timerange;
	unsigned long temp_duration;
	unsigned long temp_end;
	unsigned long temp_start;
	unsigned long start;
	unsigned long end;

	/* attempt to handle the current time_period */
	if (current_timeperiod != NULL) {

		/* "A day" is 86400 seconds */
		t = localtime(&start_time);

		/* calculate the start of the day (midnight, 00:00 hours) */
		t->tm_sec = 0;
		t->tm_min = 0;
		t->tm_hour = 0;
		t->tm_isdst = -1;
		midnight_today = (unsigned long)mktime(t);
		weekday = t->tm_wday;

		total_time = 0;
		while (midnight_today < end_time) {
			temp_duration = 0;
			temp_end = min(86400, t2 - midnight_today);
			temp_start = 0;
			if (t1 > midnight_today)
				temp_start = t1 - midnight_today;

			/* check all time ranges for this day of the week */
			for (temp_timerange = current_timeperiod->days[weekday]; temp_timerange != NULL; temp_timerange = temp_timerange->next) {
				start = max(temp_timerange->range_start, temp_start);
				end = min(temp_timerange->range_end, temp_end);
#ifdef DEBUG
				printf("<li>匹配时间范围[%d]: %d -> %d (%ld -> %ld) %d -> %d = %ld<br>\n", weekday, temp_timerange->range_start, temp_timerange->range_end, temp_start, temp_end, start, end, end - start);
#endif
				if (end > start)
					temp_duration += end - start;
			}
			total_time += temp_duration;
			temp_start = 0;
			midnight_today += 86400;
			if (++weekday > 6)
				weekday = 0;
		}

		return total_time;
	}

	/* no timeperiod was selected */
	return end_time - start_time;
}