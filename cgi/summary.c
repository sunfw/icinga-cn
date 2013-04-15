/**************************************************************************
 *
 * SUMMARY.C -  Icinga Alert Summary CGI
 *
 * Copyright (c) 2002-2008 Ethan Galstad (egalstad@nagios.org)
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

#include "../include/cgiutils.h"
#include "../include/getcgi.h"
#include "../include/cgiauth.h"


extern char main_config_file[MAX_FILENAME_LENGTH];

extern host *host_list;
extern hostgroup *hostgroup_list;
extern service *service_list;
extern servicegroup *servicegroup_list;

/* custom report types */
#define REPORT_NONE				0
#define REPORT_RECENT_ALERTS			1
#define REPORT_ALERT_TOTALS			2
#define REPORT_TOP_ALERTS			3
#define REPORT_HOSTGROUP_ALERT_TOTALS		4
#define REPORT_HOST_ALERT_TOTALS		5
#define REPORT_SERVICE_ALERT_TOTALS		6
#define REPORT_SERVICEGROUP_ALERT_TOTALS	7

/* standard report types */
#define SREPORT_NONE				0
#define SREPORT_RECENT_ALERTS			1
#define SREPORT_RECENT_HOST_ALERTS		2
#define SREPORT_RECENT_SERVICE_ALERTS		3
#define SREPORT_TOP_HOST_ALERTS			4
#define SREPORT_TOP_SERVICE_ALERTS		5

#define AE_SOFT_STATE		1
#define AE_HARD_STATE		2

#define AE_HOST_ALERT		1
#define AE_SERVICE_ALERT	2

#define AE_HOST_PRODUCER	1
#define AE_SERVICE_PRODUCER	2

#define AE_HOST_DOWN		1
#define AE_HOST_UNREACHABLE	2
#define AE_HOST_UP		4
#define AE_SERVICE_WARNING	8
#define AE_SERVICE_UNKNOWN	16
#define AE_SERVICE_CRITICAL	32
#define AE_SERVICE_OK		64

typedef struct archived_event_struct {
	time_t  time_stamp;
	int     event_type;
	int     entry_type;
	char    *host_name;
	char    *service_description;
	int     state;
	int     state_type;
	char    *event_info;
	struct archived_event_struct *next;
} archived_event;

typedef struct alert_producer_struct {
	int     producer_type;
	char    *host_name;
	char    *service_description;
	int     total_alerts;
	struct alert_producer_struct *next;
} alert_producer;

void read_archived_event_data(void);
void compute_report_times(void);
void determine_standard_report_options(void);
void add_archived_event(int, time_t, int, int, char *, char *, char *);
alert_producer *find_producer(int, char *, char *);
alert_producer *add_producer(int, char *, char *);
void free_event_list(void);
void free_producer_list(void);

void sort_archive_states(void);

void display_report(void);
void display_recent_alerts(void);
void display_top_alerts(void);
void display_alerts(void);

int process_cgivars(void);

archived_event *event_list = NULL;
alert_producer *producer_list = NULL;

authdata current_authdata;

time_t t1;
time_t t2;

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

int compute_time_from_parts = FALSE;
int timeperiod_type = TIMEPERIOD_CUSTOM;

int state_types = AE_HARD_STATE + AE_SOFT_STATE;
int alert_types = AE_HOST_ALERT + AE_SERVICE_ALERT;
int host_states = AE_HOST_UP + AE_HOST_DOWN + AE_HOST_UNREACHABLE;
int service_states = AE_SERVICE_OK + AE_SERVICE_WARNING + AE_SERVICE_UNKNOWN + AE_SERVICE_CRITICAL;

char *target_hostgroup_name = "";
char *target_servicegroup_name = "";
char *target_host_name = "";
host *target_host = NULL;
hostgroup *target_hostgroup = NULL;
service *target_service = NULL;
servicegroup *target_servicegroup = NULL;

int earliest_archive = 0;
int item_limit = 25;
int total_items = 0;

extern int embedded;
extern int display_header;
extern int daemon_check;
extern int content_type;

extern char *csv_delimiter;
extern char *csv_data_enclosure;

int json_list_start = TRUE;

int display_type = REPORT_RECENT_ALERTS;
int show_all_hosts = TRUE;
int show_all_hostgroups = TRUE;
int show_all_servicegroups = TRUE;

int standard_report = SREPORT_NONE;
int generate_report = FALSE;

int CGI_ID = SUMMARY_CGI_ID;

int main(int argc, char **argv) {
	int result = OK;
	char temp_buffer[MAX_INPUT_BUFFER];
	char start_timestring[MAX_DATETIME_LENGTH];
	char end_timestring[MAX_DATETIME_LENGTH];
	host *temp_host;
	int days, hours, minutes, seconds;
	hostgroup *temp_hostgroup;
	servicegroup *temp_servicegroup;
	time_t t3;
	time_t current_time;
	struct tm *t;
	int x;

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

	/* initialize report time period to last 24 hours */
	time(&t2);
	t1 = (time_t)(t2 - (60 * 60 * 24));

	/* get the arguments passed in the URL */
	process_cgivars();

	document_header(CGI_ID, TRUE, "事件摘要");

	/* get authentication information */
	get_authentication_information(&current_authdata);

	if (standard_report != SREPORT_NONE)
		determine_standard_report_options();

	if (compute_time_from_parts == TRUE)
		compute_report_times();

	/* make sure times are sane, otherwise swap them */
	if (t2 < t1) {
		t3 = t2;
		t2 = t1;
		t1 = t3;
	}

	if (display_header == TRUE) {

		/* begin top table */
		printf("<table border=0 width=100%% cellspacing=0 cellpadding=0>\n");
		printf("<tr>\n");

		/* left column of the first row */
		printf("<td align=left valign=top width=33%%>\n");

		snprintf(temp_buffer, sizeof(temp_buffer) - 1, "警告摘要报告");
		temp_buffer[sizeof(temp_buffer)-1] = '\x0';
		display_info_table(temp_buffer, &current_authdata, daemon_check);

		printf("</td>\n");

		/* center column of top row */
		printf("<td align=center valign=top width=33%%>\n");

		if (generate_report == TRUE) {

			printf("<DIV ALIGN=CENTER CLASS='dataTitle'>\n");
			if (display_type == REPORT_TOP_ALERTS)
				printf("警告排名");
			else if (display_type == REPORT_ALERT_TOTALS || display_type == REPORT_HOSTGROUP_ALERT_TOTALS || display_type == REPORT_SERVICEGROUP_ALERT_TOTALS || display_type == REPORT_HOST_ALERT_TOTALS || display_type == REPORT_SERVICE_ALERT_TOTALS)
				printf("警告总计");
			else

			if (show_all_hostgroups == FALSE)
				printf("主机组 '%s'", target_hostgroup_name);
			else if (show_all_servicegroups == FALSE)
				printf("服务组 '%s'", target_servicegroup_name);
			else if (show_all_hosts == FALSE)
				printf("主机 '%s'", target_host_name);
            
                printf("最近警告");

			printf("</DIV>\n");

			printf("<BR>\n");

			get_time_string(&t1, start_timestring, sizeof(start_timestring) - 1, SHORT_DATE_TIME);
			get_time_string(&t2, end_timestring, sizeof(end_timestring) - 1, SHORT_DATE_TIME);
			printf("<div align=center class='reportRange'>%s 到 %s</div>\n", start_timestring, end_timestring);

			get_time_breakdown((time_t)(t2 - t1), &days, &hours, &minutes, &seconds);
			printf("<div align=center class='reportDuration'>持续时间: %02d天%02d时%02d分%02d秒</div>\n", days, hours, minutes, seconds);
		}

		printf("</td>\n");

		/* right hand column of top row */
		printf("<td align=right valign=bottom width=33%%>\n");

		if (generate_report == TRUE) {

			printf("<table border=0>\n");

			printf("<tr>\n");
			printf("<td valign=top align=left class='optBoxTitle' colspan=2>摘要报告选项:</td>\n");
			printf("</tr>\n");

			printf("<tr>\n");
			printf("<td valign=top align=left class='optBoxItem'>警告类型:</td>\n");
			printf("<td valign=top align=left class='optBoxValue'>\n");
			if (alert_types & AE_HOST_ALERT)
				printf("主机");
			if (alert_types & AE_SERVICE_ALERT)
				printf("%s服务", (alert_types & AE_HOST_ALERT) ? " &amp; " : "");
			printf("警告</td>\n");
			printf("</tr>\n");

			printf("<tr>\n");
			printf("<td valign=top align=left class='optBoxItem'>状态类型:</td>\n");
			printf("<td valign=top align=left class='optBoxValue'>");
			if (state_types & AE_SOFT_STATE)
				printf("软件");
			if (state_types & AE_HARD_STATE)
				printf("%s硬件", (state_types & AE_SOFT_STATE) ? " &amp; " : "");
			printf("状态</td>\n");
			printf("</tr>\n");

			printf("<tr>\n");
			printf("<td valign=top align=left class='optBoxItem'>主机状态:</td>\n");
			printf("<td valign=top align=left class='optBoxValue'>");
			x = 0;
			if (host_states & AE_HOST_UP) {
				printf("运行");
				x = 1;
			}
			if (host_states & AE_HOST_DOWN) {
				printf("%s宕机", (x == 1) ? ", " : "");
				x = 1;
			}
			if (host_states & AE_HOST_UNREACHABLE)
				printf("%s不可达", (x == 1) ? ", " : "");
			if (x == 0)
				printf("无");
			printf("</td>\n");
			printf("</tr>\n");

			printf("<tr>\n");
			printf("<td valign=top align=left class='optBoxItem'>服务状态:</td>\n");
			printf("<td valign=top align=left class='optBoxValue'>");
			x = 0;
			if (service_states & AE_SERVICE_OK) {
				printf("正常");
				x = 1;
			}
			if (service_states & AE_SERVICE_WARNING) {
				printf("%s警报", (x == 1) ? ", " : "");
				x = 1;
			}
			if (service_states & AE_SERVICE_UNKNOWN) {
				printf("%s未知", (x == 1) ? ", " : "");
				x = 1;
			}
			if (service_states & AE_SERVICE_CRITICAL)
				printf("%s紧急", (x == 1) ? ", " : "");
			if (x == 0)
				printf("无");
			printf("</td>\n");
			printf("</tr>\n");

			printf("<tr>\n");
			printf("<td valign=top align=left colspan=2 class='optBoxItem'>\n");
			printf("<form action='%s' method='GET'>\n", SUMMARY_CGI);
			printf("<input type='submit' name='btnSubmit' value='生成新报告'>\n");
			printf("</form>\n");
			printf("</td>\n");
			printf("</tr>\n");
			printf("</table>\n");
		}

		printf("</td>\n");

		/* end of top table */
		printf("</tr>\n");
		printf("</table>\n");
	}


	/*********************************/
	/****** GENERATE THE REPORT ******/
	/*********************************/

	if (generate_report == TRUE) {
		read_archived_event_data();
		display_report();
	}

	/* ask user for report options */
	else {

		time(&current_time);
		t = localtime(&current_time);

		start_day = 1;
		start_year = t->tm_year + 1900;
		end_day = t->tm_mday;
		end_year = t->tm_year + 1900;

		printf("<DIV ALIGN=CENTER CLASS='dateSelectTitle'>标准报告:</DIV>\n");
		printf("<form method=\"get\" action=\"%s\">\n", SUMMARY_CGI);

		printf("<input type='hidden' name='report' value='1'>\n");

		printf("<table border=0 cellpadding=5 align='center'>\n");
		printf("<tr><td class='reportSelectSubTitle' align=right>报告类型:</td>\n");
		printf("<td class='reportSelectItem'>\n");
		printf("<select name='standardreport'>\n");
		printf("<option value=%d>25个最新硬件状态警告\n", SREPORT_RECENT_ALERTS);
		printf("<option value=%d>25个最新硬件状态主机警告\n", SREPORT_RECENT_HOST_ALERTS);
		printf("<option value=%d>25个最新硬件状态服务警告\n", SREPORT_RECENT_SERVICE_ALERTS);
		printf("<option value=%d>前25个硬件状态主机警告排名s\n", SREPORT_TOP_HOST_ALERTS);
		printf("<option value=%d>前25个硬件状态服务警告排名\n", SREPORT_TOP_SERVICE_ALERTS);
		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr><td></td><td align=left class='dateSelectItem'><input type='submit' value='生成摘要报告!'></td></tr>\n");

		printf("</table>\n");

		printf("</form>\n");


		printf("<DIV ALIGN=CENTER CLASS='dateSelectTitle'>自定义报告选项:</DIV>\n");

		printf("<form method=\"get\" action=\"%s\">\n", SUMMARY_CGI);

		printf("<input type='hidden' name='report' value='1'>\n");

		printf("<table border=0 cellpadding=5 align='center'>\n");

		printf("<tr><td class='reportSelectSubTitle' align=right>报告类型:</td>\n");
		printf("<td class='reportSelectItem'>\n");
		printf("<select name='displaytype'>\n");
		printf("<option value=%d>最新警告\n", REPORT_RECENT_ALERTS);
		printf("<option value=%d>警告总计\n", REPORT_ALERT_TOTALS);
		printf("<option value=%d>主机组警告总计\n", REPORT_HOSTGROUP_ALERT_TOTALS);
		printf("<option value=%d>主机警告总计\n", REPORT_HOST_ALERT_TOTALS);
		printf("<option value=%d>服务组警告总计\n", REPORT_SERVICEGROUP_ALERT_TOTALS);
		printf("<option value=%d>服务警告总计\n", REPORT_SERVICE_ALERT_TOTALS);
		printf("<option value=%d>警告排名\n", REPORT_TOP_ALERTS);
		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr>");
		printf("<td valign=top class='reportSelectSubTitle'>报告周期:</td>\n");
		printf("<td valign=top align=left class='optBoxItem'>\n");
		printf("<select name='timeperiod'>\n");
		printf("<option value=today>今天\n");
		printf("<option value=last24hours>最近24小时\n");
		printf("<option value=yesterday>昨天\n");
		printf("<option value=thisweek>本周\n");
		printf("<option value=last7days SELECTED>最近7天\n");
		printf("<option value=lastweek>上周\n");
		printf("<option value=thismonth>本月\n");
		printf("<option value=last31days>最近31天\n");
		printf("<option value=lastmonth>上月\n");
		printf("<option value=thisyear>今年\n");
		printf("<option value=lastyear>去年\n");
		printf("<option value=custom>* 自定义的报告时段 *\n");
		printf("</select>\n");
		printf("</td>\n");
		printf("</tr>\n");

		printf("<tr><td valign=top class='reportSelectSubTitle'>如果自定义报告周期...</td></tr>\n");

		printf("<tr>");
		printf("<td valign=top class='reportSelectSubTitle'>开始时间(含):</td>\n");
		printf("<td align=left valign=top class='reportSelectItem'>");
		printf("<select name='smon'>\n");
		printf("<option value='1' %s>一月\n",(t->tm_mon == 0)?"SELECTED":"");
		printf("<option value='2' %s>二月\n",(t->tm_mon == 1)?"SELECTED":"");
		printf("<option value='3' %s>三月\n",(t->tm_mon == 2)?"SELECTED":"");
		printf("<option value='4' %s>四月\n",(t->tm_mon == 3)?"SELECTED":"");
		printf("<option value='5' %s>五月\n",(t->tm_mon == 4)?"SELECTED":"");
		printf("<option value='6' %s>六月\n",(t->tm_mon == 5)?"SELECTED":"");
		printf("<option value='7' %s>七月\n",(t->tm_mon == 6)?"SELECTED":"");
		printf("<option value='8' %s>八月\n",(t->tm_mon == 7)?"SELECTED":"");
		printf("<option value='9' %s>九月\n",(t->tm_mon == 8) ? "SELECTED":"");
		printf("<option value='10' %s>十月\n",(t->tm_mon == 9) ? "SELECTED":"");
		printf("<option value='11' %s>十一月\n",(t->tm_mon == 10)?"SELECTED":"");
		printf("<option value='12' %s>十二月\n",(t->tm_mon == 11)?"SELECTED":"");
		printf("</select>\n ");
		printf("<input type='text' size='2' maxlength='2' name='sday' value='%d'> ", start_day);
		printf("<input type='text' size='4' maxlength='4' name='syear' value='%d'>", start_year);
		printf("<input type='hidden' name='shour' value='0'>\n");
		printf("<input type='hidden' name='smin' value='0'>\n");
		printf("<input type='hidden' name='ssec' value='0'>\n");
		printf("</td>\n");
		printf("</tr>\n");

		printf("<tr>");
		printf("<td valign=top class='reportSelectSubTitle'>结束时间(含):</td>\n");
		printf("<td align=left valign=top class='reportSelectItem'>");
		printf("<select name='emon'>\n");
		printf("<option value='1' %s>一月\n",(t->tm_mon == 0)?"SELECTED":"");
		printf("<option value='2' %s>二月\n",(t->tm_mon == 1)?"SELECTED":"");
		printf("<option value='3' %s>三月\n",(t->tm_mon == 2)?"SELECTED":"");
		printf("<option value='4' %s>四月\n",(t->tm_mon == 3)?"SELECTED":"");
		printf("<option value='5' %s>五月\n",(t->tm_mon == 4)?"SELECTED":"");
		printf("<option value='6' %s>六月\n",(t->tm_mon == 5)?"SELECTED":"");
		printf("<option value='7' %s>七月\n",(t->tm_mon == 6)?"SELECTED":"");
		printf("<option value='8' %s>八月\n",(t->tm_mon == 7)?"SELECTED":"");
		printf("<option value='9' %s>九月\n",(t->tm_mon == 8)?"SELECTED":"");
		printf("<option value='10' %s>十月\n",(t->tm_mon == 9)?"SELECTED":"");
		printf("<option value='11' %s>十一月\n",(t->tm_mon == 10)?"SELECTED":"");
		printf("<option value='12' %s>十二月\n",(t->tm_mon == 11)?"SELECTED":"");
		printf("</select>\n ");
		printf("<input type='text' size='2' maxlength='2' name='eday' value='%d'> ", end_day);
		printf("<input type='text' size='4' maxlength='4' name='eyear' value='%d'>", end_year);
		printf("<input type='hidden' name='ehour' value='24'>\n");
		printf("<input type='hidden' name='emin' value='0'>\n");
		printf("<input type='hidden' name='esec' value='0'>\n");
		printf("</td>\n");
		printf("</tr>\n");

		printf("<tr><td colspan=2><br></td></tr>\n");

		printf("<tr><td class='reportSelectSubTitle' valign=center>限制主机组:</td><td align=left valign=center class='reportSelectItem'>\n");
		printf("<select name='hostgroup'>\n");
		printf("<option value='all'>** 所有主机组 **\n");
		for (temp_hostgroup = hostgroup_list; temp_hostgroup != NULL; temp_hostgroup = temp_hostgroup->next) {
			if (is_authorized_for_hostgroup(temp_hostgroup, &current_authdata) == TRUE)
				printf("<option value='%s'>%s\n", escape_string(temp_hostgroup->group_name), temp_hostgroup->group_name);
		}
		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr><td class='reportSelectSubTitle' valign=center>限制服务组:</td><td align=left valign=center class='reportSelectItem'>\n");
		printf("<select name='servicegroup'>\n");
		printf("<option value='all'>** 所有服务组 **\n");
		for (temp_servicegroup = servicegroup_list; temp_servicegroup != NULL; temp_servicegroup = temp_servicegroup->next) {
			if (is_authorized_for_servicegroup(temp_servicegroup, &current_authdata) == TRUE)
				printf("<option value='%s'>%s\n", escape_string(temp_servicegroup->group_name), temp_servicegroup->group_name);
		}
		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr><td class='reportSelectSubTitle' valign=center>限制主机:</td><td align=left valign=center class='reportSelectItem'>\n");
		printf("<select name='host'>\n");
		printf("<option value='all'>** 所有主机 **\n");

		for (temp_host = host_list; temp_host != NULL; temp_host = temp_host->next) {
			if (is_authorized_for_host(temp_host, &current_authdata) == TRUE)
				printf("<option value='%s'>%s\n", escape_string(temp_host->name), temp_host->name);
		}
		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr><td class='reportSelectSubTitle' align=right>警告类型:</td>\n");
		printf("<td class='reportSelectItem'>\n");
		printf("<select name='alerttypes'>\n");
		printf("<option value=%d %s>主机和服务警告\n", AE_HOST_ALERT + AE_SERVICE_ALERT, (alert_types == AE_HOST_ALERT + AE_SERVICE_ALERT) ? "SELECTED" : "");
		printf("<option value=%d %s>主机警告\n", AE_HOST_ALERT, (alert_types == AE_HOST_ALERT) ? "SELECTED" : "");
		printf("<option value=%d %s>服务警告\n", AE_SERVICE_ALERT, (alert_types == AE_SERVICE_ALERT) ? "SELECTED" : "");
		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr><td class='reportSelectSubTitle' align=right>状态类型:</td>\n");
		printf("<td class='reportSelectItem'>\n");
		printf("<select name='statetypes'>\n");
		printf("<option value=%d %s>硬件和软件状态\n", AE_HARD_STATE + AE_SOFT_STATE, (state_types == AE_HARD_STATE + AE_SOFT_STATE) ? "SELECTED" : "");
		printf("<option value=%d %s>硬件状态\n", AE_HARD_STATE, (state_types == AE_HARD_STATE) ? "SELECTED" : "");
		printf("<option value=%d %s>软件状态\n", AE_SOFT_STATE, (state_types == AE_SOFT_STATE) ? "SELECTED" : "");
		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr><td class='reportSelectSubTitle' align=right>主机状态:</td>\n");
		printf("<td class='reportSelectItem'>\n");
		printf("<select name='hoststates'>\n");
		printf("<option value=%d>所有主机状态\n", AE_HOST_UP + AE_HOST_DOWN + AE_HOST_UNREACHABLE);
		printf("<option value=%d>主机故障状态\n", AE_HOST_DOWN + AE_HOST_UNREACHABLE);
		printf("<option value=%d>主机运行状态\n", AE_HOST_UP);
		printf("<option value=%d>主机主机宕机状态\n", AE_HOST_DOWN);
		printf("<option value=%d>主机不可达状态\n", AE_HOST_UNREACHABLE);
		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr><td class='reportSelectSubTitle' align=right>服务状态:</td>\n");
		printf("<td class='reportSelectItem'>\n");
		printf("<select name='servicestates'>\n");
		printf("<option value=%d>所有服务状态\n", AE_SERVICE_OK + AE_SERVICE_WARNING + AE_SERVICE_UNKNOWN + AE_SERVICE_CRITICAL);
		printf("<option value=%d>服务故障状态\n", AE_SERVICE_WARNING + AE_SERVICE_UNKNOWN + AE_SERVICE_CRITICAL);
		printf("<option value=%d>服务正常状态\n", AE_SERVICE_OK);
		printf("<option value=%d>服务警报状态\n", AE_SERVICE_WARNING);
		printf("<option value=%d>服务未知状态\n", AE_SERVICE_UNKNOWN);
		printf("<option value=%d>服务紧急状态\n", AE_SERVICE_CRITICAL);
		printf("</select>\n");
		printf("</td></tr>\n");

		printf("<tr><td class='reportSelectSubTitle' align=right>最大列表项:</td>\n");
		printf("<td class='reportSelectItem'>\n");
		printf("<input type='text' name='limit' size='3' maxlength='3' value='%d'>\n", item_limit);
		printf("</td></tr>\n");

		printf("<tr><td></td><td align=left class='dateSelectItem'><input type='submit' value='生成摘要报告!'></td></tr>\n");

		printf("</table>\n");

		printf("</form>\n");
	}


	document_footer(CGI_ID);

	/* free all other allocated memory */
	free_memory();
	free_event_list();
	free_producer_list();

	return OK;
}

int process_cgivars(void) {
	char **variables;
	int error = FALSE;
	int x;

	variables = getcgivars();

	for (x = 0; variables[x] != NULL; x++) {

		/* do some basic length checking on the variable identifier to prevent buffer overflows */
		if (strlen(variables[x]) >= MAX_INPUT_BUFFER - 1) {
			x++;
			continue;
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

		/* we found the embed option */
		else if (!strcmp(variables[x], "embedded"))
			embedded = TRUE;

		/* we found the noheader option */
		else if (!strcmp(variables[x], "noheader"))
			display_header = FALSE;

		/* we found the nodaemoncheck option */
		else if (!strcmp(variables[x], "nodaemoncheck"))
			daemon_check = FALSE;

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

		/* we found the item limit argument */
		else if (!strcmp(variables[x], "limit")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			item_limit = atoi(variables[x]);
		}

		/* we found the state types argument */
		else if (!strcmp(variables[x], "statetypes")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			state_types = atoi(variables[x]);
		}

		/* we found the alert types argument */
		else if (!strcmp(variables[x], "alerttypes")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			alert_types = atoi(variables[x]);
		}

		/* we found the host states argument */
		else if (!strcmp(variables[x], "hoststates")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			host_states = atoi(variables[x]);
		}

		/* we found the service states argument */
		else if (!strcmp(variables[x], "servicestates")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			service_states = atoi(variables[x]);
		}

		/* we found the generate report argument */
		else if (!strcmp(variables[x], "report")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			generate_report = (atoi(variables[x]) > 0) ? TRUE : FALSE;
		}


		/* we found the display type argument */
		else if (!strcmp(variables[x], "displaytype")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			display_type = atoi(variables[x]);
		}

		/* we found the standard report argument */
		else if (!strcmp(variables[x], "standardreport")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			standard_report = atoi(variables[x]);
		}

		/* we found the hostgroup argument */
		else if (!strcmp(variables[x], "hostgroup")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if ((target_hostgroup_name = (char *)strdup(variables[x])) == NULL)
				target_hostgroup_name = "";
			strip_html_brackets(target_hostgroup_name);

			if (!strcmp(target_hostgroup_name, "all"))
				show_all_hostgroups = TRUE;
			else {
				show_all_hostgroups = FALSE;
				target_hostgroup = find_hostgroup(target_hostgroup_name);
			}
		}

		/* we found the servicegroup argument */
		else if (!strcmp(variables[x], "servicegroup")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if ((target_servicegroup_name = (char *)strdup(variables[x])) == NULL)
				target_servicegroup_name = "";
			strip_html_brackets(target_servicegroup_name);

			if (!strcmp(target_servicegroup_name, "all"))
				show_all_servicegroups = TRUE;
			else {
				show_all_servicegroups = FALSE;
				target_servicegroup = find_servicegroup(target_servicegroup_name);
			}
		}

		/* we found the host argument */
		else if (!strcmp(variables[x], "host")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if ((target_host_name = (char *)strdup(variables[x])) == NULL)
				target_host_name = "";
			strip_html_brackets(target_host_name);

			if (!strcmp(target_host_name, "all"))
				show_all_hosts = TRUE;
			else {
				show_all_hosts = FALSE;
				target_host = find_host(target_host_name);
			}
		}
	}

	/* free memory allocated to the CGI variables */
	free_cgivars(variables);

	return error;
}

/* reads log files for archived event data */
void read_archived_event_data(void) {
	char entry_host_name[MAX_INPUT_BUFFER];
	char entry_svc_description[MAX_INPUT_BUFFER];
	char *temp_buffer;
	char *plugin_output;
	char *error_text = NULL;
	int state;
	int state_type;
	int status = READLOG_OK;
	logentry *temp_entry = NULL;
	logentry *entry_list = NULL;
	logfilter *filter_list = NULL;

	/* add host filter */
	add_log_filter(&filter_list, LOGENTRY_HOST_UP, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_HOST_DOWN, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_HOST_UNREACHABLE, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_HOST_RECOVERY, LOGFILTER_INCLUDE);

	/* add service filter */
	add_log_filter(&filter_list, LOGENTRY_SERVICE_OK, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_SERVICE_WARNING, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_SERVICE_CRITICAL, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_SERVICE_UNKNOWN, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_SERVICE_RECOVERY, LOGFILTER_INCLUDE);

	/* read log entries */
	status = get_log_entries(&entry_list, &filter_list, &error_text, NULL, FALSE, t1, t2);

	free_log_filters(&filter_list);

	if (status == READLOG_OK) {

		for (temp_entry = entry_list; temp_entry != NULL; temp_entry = temp_entry->next) {

			/* get the timestamp */
			if (temp_entry->timestamp < t1 || temp_entry->timestamp > t2)
				continue;

			switch (temp_entry->type) {

				/* host alerts */
			case LOGENTRY_HOST_DOWN:
			case LOGENTRY_HOST_UNREACHABLE:
			case LOGENTRY_HOST_RECOVERY:
			case LOGENTRY_HOST_UP:

				/* get host name */
				temp_buffer = my_strtok(temp_entry->entry_text, ":");
				temp_buffer = my_strtok(NULL, ";");
				strncpy(entry_host_name, (temp_buffer == NULL) ? "" : temp_buffer + 1, sizeof(entry_host_name));
				entry_host_name[sizeof(entry_host_name)-1] = '\x0';

				/* state type */
				if (strstr(temp_entry->entry_text, ";软件状态;"))
					state_type = AE_SOFT_STATE;
				else
					state_type = AE_HARD_STATE;

				/* get the plugin output */
				temp_buffer = my_strtok(NULL, ";");
				temp_buffer = my_strtok(NULL, ";");
				temp_buffer = my_strtok(NULL, ";");
				plugin_output = my_strtok(NULL, "\n");

				/* state */
				if (temp_entry->type == LOGENTRY_HOST_DOWN)
					state = AE_HOST_DOWN;
				else if (temp_entry->type == LOGENTRY_HOST_UNREACHABLE)
					state = AE_HOST_UNREACHABLE;
				else if (temp_entry->type == LOGENTRY_HOST_RECOVERY || temp_entry->type == LOGENTRY_HOST_UP)
					state = AE_HOST_UP;
				else
					break;

				add_archived_event(AE_HOST_ALERT, temp_entry->timestamp, state, state_type, entry_host_name, NULL, plugin_output);

				break;


				/* service alerts */
			case LOGENTRY_SERVICE_CRITICAL:
			case LOGENTRY_SERVICE_WARNING:
			case LOGENTRY_SERVICE_UNKNOWN:
			case LOGENTRY_SERVICE_RECOVERY:
			case LOGENTRY_SERVICE_OK:

				/* get host name */
				temp_buffer = my_strtok(temp_entry->entry_text, ":");
				temp_buffer = my_strtok(NULL, ";");
				strncpy(entry_host_name, (temp_buffer == NULL) ? "" : temp_buffer + 1, sizeof(entry_host_name));
				entry_host_name[sizeof(entry_host_name)-1] = '\x0';

				/* get service description */
				temp_buffer = my_strtok(NULL, ";");
				strncpy(entry_svc_description, (temp_buffer == NULL) ? "" : temp_buffer, sizeof(entry_svc_description));
				entry_svc_description[sizeof(entry_svc_description)-1] = '\x0';

				/* state type */
				if (strstr(temp_entry->entry_text, ";软件状态;"))
					state_type = AE_SOFT_STATE;
				else
					state_type = AE_HARD_STATE;

				/* get the plugin output */
				temp_buffer = my_strtok(NULL, ";");
				temp_buffer = my_strtok(NULL, ";");
				temp_buffer = my_strtok(NULL, ";");
				plugin_output = my_strtok(NULL, "\n");

				/* state */
				if (temp_entry->type == LOGENTRY_SERVICE_CRITICAL)
					state = AE_SERVICE_CRITICAL;
				else if (temp_entry->type == LOGENTRY_SERVICE_WARNING)
					state = AE_SERVICE_WARNING;
				else if (temp_entry->type == LOGENTRY_SERVICE_UNKNOWN)
					state = AE_SERVICE_UNKNOWN;
				else if (temp_entry->type == LOGENTRY_SERVICE_RECOVERY || temp_entry->type == LOGENTRY_SERVICE_OK)
					state = AE_SERVICE_OK;
				else
					break;

				add_archived_event(AE_SERVICE_ALERT, temp_entry->timestamp, state, state_type, entry_host_name, entry_svc_description, plugin_output);

				break;
			}

		}
	}

	/* free memory */
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

void free_event_list(void) {
	archived_event *this_event = NULL;
	archived_event *next_event = NULL;

	for (this_event = event_list; this_event != NULL;) {
		next_event = this_event->next;
		if (this_event->host_name != NULL)
			free(this_event->host_name);
		if (this_event->service_description != NULL)
			free(this_event->service_description);
		if (this_event->event_info != NULL)
			free(this_event->event_info);
		free(this_event);
		this_event = next_event;
	}

	event_list = NULL;

	return;
}

/* adds an archived event entry to the list in memory */
void add_archived_event(int event_type, time_t time_stamp, int entry_type, int state_type, char *host_name, char *svc_description, char *event_info) {
	archived_event *new_event = NULL;
	service *temp_service = NULL;
	host *temp_host;


	/* check timestamp sanity */
	if (time_stamp < t1 || time_stamp > t2)
		return;

	/* check alert type (host or service alert) */
	if (!(alert_types & event_type))
		return;

	/* check state type (soft or hard state) */
	if (!(state_types & state_type))
		return;

	/* check state (host or service state) */
	if (event_type == AE_HOST_ALERT) {
		if (!(host_states & entry_type))
			return;
	} else {
		if (!(service_states & entry_type))
			return;
	}

	/* find the host this entry is associated with */
	temp_host = find_host(host_name);

	/* check hostgroup match (valid filter for all reports) */
	if (show_all_hostgroups == FALSE && is_host_member_of_hostgroup(target_hostgroup, temp_host) == FALSE)
		return;

	/* check host match (valid filter for some reports) */
	if (show_all_hosts == FALSE && (display_type == REPORT_RECENT_ALERTS || display_type == REPORT_HOST_ALERT_TOTALS || display_type == REPORT_SERVICE_ALERT_TOTALS)) {
		if (target_host == NULL || temp_host == NULL)
			return;
		if (strcmp(target_host->name, temp_host->name))
			return;
	}

	/* check servicegroup math (valid filter for all reports) */
	if (event_type == AE_SERVICE_ALERT) {
		temp_service = find_service(host_name, svc_description);
		if (show_all_servicegroups == FALSE && is_service_member_of_servicegroup(target_servicegroup, temp_service) == FALSE)
			return;
	} else {
		if (show_all_servicegroups == FALSE && is_host_member_of_servicegroup(target_servicegroup, temp_host) == FALSE)
			return;
	}

	/* check authorization */
	if (event_type == AE_SERVICE_ALERT) {
		if (is_authorized_for_service(temp_service, &current_authdata) == FALSE)
			return;
	} else {
		if (is_authorized_for_host(temp_host, &current_authdata) == FALSE)
			return;
	}

#ifdef DEBUG
	if (event_type == AE_HOST_ALERT)
		printf("添加主机警告 (%s) @ %lu<BR>\n", host_name, (unsigned long)time_stamp);
	else
		printf("添加服务警告 (%s/%s) @ %lu<BR>\n", host_name, svc_description, (unsigned long)time_stamp);
#endif

	/* allocate memory for the new entry */
	new_event = (archived_event *)malloc(sizeof(archived_event));
	if (new_event == NULL)
		return;

	/* allocate memory for the host name */
	if (host_name != NULL) {
		new_event->host_name = (char *)malloc(strlen(host_name) + 1);
		if (new_event->host_name != NULL)
			strcpy(new_event->host_name, host_name);
	} else
		new_event->host_name = NULL;

	/* allocate memory for the service description */
	if (svc_description != NULL) {
		new_event->service_description = (char *)malloc(strlen(svc_description) + 1);
		if (new_event->service_description != NULL)
			strcpy(new_event->service_description, svc_description);
	} else
		new_event->service_description = NULL;

	/* allocate memory for the event info */
	if (event_info != NULL) {
		new_event->event_info = (char *)malloc(strlen(event_info) + 1);
		if (new_event->event_info != NULL)
			strcpy(new_event->event_info, event_info);
	} else
		new_event->event_info = NULL;

	new_event->event_type = event_type;
	new_event->time_stamp = time_stamp;
	new_event->entry_type = entry_type;
	new_event->state_type = state_type;


	/* add the new entry to the list in memory */
	new_event->next = NULL;
	new_event->next = event_list;
	event_list = new_event;

	total_items++;

	return;
}

void sort_archive_states(void) {
	archived_event *temp_list = NULL;
	archived_event *new_event = NULL;
	archived_event *last_event = NULL;
	archived_event *next_event = NULL;
	archived_event *temp_event = NULL;

	temp_list = NULL;
	for (new_event = event_list; new_event != NULL;) {
		next_event = new_event->next;

		last_event = temp_list;
		for (temp_event = temp_list; temp_event != NULL; temp_event = temp_event->next) {
			if (new_event->time_stamp >= temp_event->time_stamp) {
				new_event->next = temp_event;
				if (temp_event == temp_list)
					temp_list = new_event;
				else
					last_event->next = new_event;
				break;
			} else
				last_event = temp_event;
		}

		if (temp_list == NULL) {
			new_event->next = NULL;
			temp_list = new_event;
		} else if (temp_event == NULL) {
			new_event->next = NULL;
			last_event->next = new_event;
		}

		new_event = next_event;
	}
	event_list = temp_list;

	return;
}


/* determines standard report options */
void determine_standard_report_options(void) {

	/* report over last 7 days */
	convert_timeperiod_to_times(TIMEPERIOD_LAST7DAYS, &t1, &t2);
	compute_time_from_parts = FALSE;

	/* common options */
	state_types = AE_HARD_STATE;
	item_limit = 25;

	/* report-specific options */
	switch (standard_report) {

	case SREPORT_RECENT_ALERTS:
		display_type = REPORT_RECENT_ALERTS;
		alert_types = AE_HOST_ALERT + AE_SERVICE_ALERT;
		host_states = AE_HOST_UP + AE_HOST_DOWN + AE_HOST_UNREACHABLE;
		service_states = AE_SERVICE_OK + AE_SERVICE_WARNING + AE_SERVICE_UNKNOWN + AE_SERVICE_CRITICAL;
		break;

	case SREPORT_RECENT_HOST_ALERTS:
		display_type = REPORT_RECENT_ALERTS;
		alert_types = AE_HOST_ALERT;
		host_states = AE_HOST_UP + AE_HOST_DOWN + AE_HOST_UNREACHABLE;
		break;

	case SREPORT_RECENT_SERVICE_ALERTS:
		display_type = REPORT_RECENT_ALERTS;
		alert_types = AE_SERVICE_ALERT;
		service_states = AE_SERVICE_OK + AE_SERVICE_WARNING + AE_SERVICE_UNKNOWN + AE_SERVICE_CRITICAL;
		break;

	case SREPORT_TOP_HOST_ALERTS:
		display_type = REPORT_TOP_ALERTS;
		alert_types = AE_HOST_ALERT;
		host_states = AE_HOST_UP + AE_HOST_DOWN + AE_HOST_UNREACHABLE;
		break;

	case SREPORT_TOP_SERVICE_ALERTS:
		display_type = REPORT_TOP_ALERTS;
		alert_types = AE_SERVICE_ALERT;
		service_states = AE_SERVICE_OK + AE_SERVICE_WARNING + AE_SERVICE_UNKNOWN + AE_SERVICE_CRITICAL;
		break;

	default:
		break;
	}

	return;
}

/* displays report */
void display_report(void) {
	hostgroup *temp_hostgroup;
	host *temp_host;
	service *temp_service;
	servicegroup* temp_servicegroup;

	if (display_type == REPORT_TOP_ALERTS) {
		display_top_alerts();
		return;
	}

	if (display_type == REPORT_RECENT_ALERTS) {
		display_recent_alerts();
		return;
	}

	if (content_type == JSON_CONTENT) {
		if (display_type == REPORT_ALERT_TOTALS)
			printf("\"全部警告总计\": [\n");
		if (display_type == REPORT_HOST_ALERT_TOTALS)
			printf("\"主机警告总计\": {\n");
		if (display_type == REPORT_HOSTGROUP_ALERT_TOTALS)
			printf("\"主机组警告总计\": {\n");
		if (display_type == REPORT_SERVICE_ALERT_TOTALS)
			printf("\"服务警告总计\": {\n");
		if (display_type == REPORT_SERVICEGROUP_ALERT_TOTALS)
			printf("\"服务组警告总计\": {\n");

	} else if (content_type == CSV_CONTENT) {
		if (display_type == REPORT_HOST_ALERT_TOTALS || display_type == REPORT_SERVICE_ALERT_TOTALS)
			printf("%s主机名称%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		if (display_type == REPORT_HOSTGROUP_ALERT_TOTALS)
			printf("%s主机组名称%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		if (display_type == REPORT_SERVICE_ALERT_TOTALS)
			printf("%s服务%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		if (display_type == REPORT_SERVICEGROUP_ALERT_TOTALS)
			printf("%s服务组名称%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);

		/* Host Alerts Data */
		if (alert_types & AE_HOST_ALERT && display_type != REPORT_SERVICE_ALERT_TOTALS) {
			printf("%s主机运行软件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s主机运行硬件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s主机运行总计%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s主机宕机软件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s主机宕机硬件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s主机宕机总计%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s主机不可达软件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s主机不可达硬件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s主机不可达总计%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s主机所有软件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s主机所有硬件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s主机所有总计%s", csv_data_enclosure, csv_data_enclosure);
		}

		/* Service Alerts Head */
		if (alert_types & AE_SERVICE_ALERT) {
			if (alert_types & AE_HOST_ALERT && display_type != REPORT_SERVICE_ALERT_TOTALS)
				printf("%s", csv_delimiter);
			printf("%s服务正常软件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s服务正常硬件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s服务正常总计%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s服务警报软件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s服务警报硬件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s服务警报总计%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s服务未知软件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s服务未知硬件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s服务未知总计%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s服务紧急软件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s服务紧急硬件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s服务紧急总计%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s服务所有软件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s服务所有硬件状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s服务所有总计%s\n", csv_data_enclosure, csv_data_enclosure);
		} else {
			printf("\n");
		}
	} else {
		printf("<BR>\n");

		printf("<table align=\"CENTER\" border=\"0\"><tr><td>");
		printf("<DIV ALIGN=CENTER CLASS='dataSubTitle'>");
		if (display_type == REPORT_ALERT_TOTALS)
			printf("全部总计");
		if (display_type == REPORT_HOST_ALERT_TOTALS)
			printf("主机总计");
		if (display_type == REPORT_HOSTGROUP_ALERT_TOTALS)
			printf("主机组总计");
		if (display_type == REPORT_SERVICE_ALERT_TOTALS)
			printf("服务总计");
		if (display_type == REPORT_SERVICEGROUP_ALERT_TOTALS)
			printf("服务组总计");

		printf("</DIV>\n");

		/* add export to csv, json, link */
		printf("<div class='csv_export_link'>");
		print_export_link(CSV_CONTENT, SUMMARY_CGI, NULL);
		print_export_link(JSON_CONTENT, SUMMARY_CGI, NULL);
		print_export_link(HTML_CONTENT, SUMMARY_CGI, NULL);
		printf("</div>\n");
	}

	if (display_type == REPORT_ALERT_TOTALS) {
		display_alerts();
	}
	if (display_type == REPORT_HOST_ALERT_TOTALS) {
		if (show_all_hosts == FALSE)
			display_alerts();
		else {
			for (temp_host = host_list; temp_host != NULL; temp_host = temp_host->next) {
				target_host = temp_host;
				display_alerts();
			}
		}
	}
	if (display_type == REPORT_HOSTGROUP_ALERT_TOTALS) {
		if (show_all_hostgroups == FALSE)
			display_alerts();
		else {
			for (temp_hostgroup = hostgroup_list; temp_hostgroup != NULL; temp_hostgroup = temp_hostgroup->next) {
				target_hostgroup = temp_hostgroup;
				display_alerts();
			}
		}
	}
	if (display_type == REPORT_SERVICE_ALERT_TOTALS) {
		for (temp_service = service_list; temp_service != NULL; temp_service = temp_service->next) {
			target_service = temp_service;
			display_alerts();
		}
	}
	if (display_type == REPORT_SERVICEGROUP_ALERT_TOTALS) {
		if (show_all_servicegroups == FALSE)
			display_alerts();
		else {
			for (temp_servicegroup = servicegroup_list; temp_servicegroup != NULL; temp_servicegroup = temp_servicegroup->next) {
				target_servicegroup = temp_servicegroup;
				display_alerts();
			}
		}
	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT) {
		printf("</td></tr></table>");
	} else if (content_type == JSON_CONTENT) {
		printf("\n]\n");
		if (display_type != REPORT_ALERT_TOTALS)
			printf("\n}\n");
	}

	return;
}

/* displays recent alerts */
void display_recent_alerts(void) {
	archived_event *temp_event;
	int current_item = 0;
	int odd = 0;
	int json_start = TRUE;
	char *status_bgclass = "";
	char *status = "";
	char date_time[MAX_DATETIME_LENGTH];

	host *temp_host = NULL;
	service *temp_service = NULL;

	if (content_type == JSON_CONTENT)
		printf("\"最近警告\": [\n");
	else if (content_type == CSV_CONTENT) {
		printf("%s时间%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s警告类型E%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s主机%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s服务%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s状态%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s状态类型%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s信息%s\n", csv_data_enclosure, csv_data_enclosure);
	} else {
		printf("<BR>\n");

		if (item_limit <= 0 || total_items <= item_limit || total_items == 0)
			printf("<DIV ALIGN=CENTER CLASS='dataSubTitle'>显示所有%d匹配的警告\n", total_items);
		else
			printf("<DIV ALIGN=CENTER CLASS='dataSubTitle'>显示最新%d/%d匹配的警告\n", item_limit, total_items);

		printf("<TABLE BORDER=0 CLASS='data' align='center'>\n");

		printf("<TR><TD colspan='7'>");
		/* add export to csv, json, link */
		printf("<div class='csv_export_link'>");
		print_export_link(CSV_CONTENT, SUMMARY_CGI, NULL);
		print_export_link(JSON_CONTENT, SUMMARY_CGI, NULL);
		print_export_link(HTML_CONTENT, SUMMARY_CGI, NULL);
		printf("</div>\n");
		printf("</TD></TR>\n");

		printf("<TR><TH CLASS='data'>时间</TH><TH CLASS='data'>警告类型</TH><TH CLASS='data'>主机</TH><TH CLASS='data'>服务</TH><TH CLASS='data'>状态</TH><TH CLASS='data'>状态类型</TH><TH CLASS='data'>信息</TH></TR>\n");
	}

	sort_archive_states();

	for (temp_event = event_list; temp_event != NULL; temp_event = temp_event->next, current_item++) {

		if (current_item >= item_limit && item_limit > 0)
			break;

		if (odd)
			odd = 0;
		else
			odd = 1;

		/* find the host */
		temp_host = find_host(temp_event->host_name);

		/* find the service */
		temp_service = find_service(temp_event->host_name, temp_event->service_description);

		get_time_string(&temp_event->time_stamp, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);

		if (content_type == JSON_CONTENT) {
			// always add a comma, except for the first line
			if (json_start == FALSE)
				printf(",\n");
			json_start = FALSE;
			printf("{ \"时间\": \"%s\", ", date_time);
			printf("\"警告类型\": \"%s\", ", (temp_event->event_type == AE_HOST_ALERT) ? "主机警告" : "服务警告");
			printf("\"主机名称\": \"%s\", ", json_encode(temp_host->name));
			printf("\"主机显示名称\": \"%s\", ", (temp_host->display_name != NULL) ? json_encode(temp_host->display_name) : json_encode(temp_host->name));
			if (temp_event->event_type == AE_HOST_ALERT) {
				printf("\"服务描述\": null, ");
				printf("\"服务显示名称\": null, ");
			} else {
				printf("\"服务描述\": \"%s\", ", json_encode(temp_service->description));
				printf("\"服务显示名称\": \"%s\", ", (temp_service->display_name != NULL) ? json_encode(temp_service->display_name) : json_encode(temp_service->description));
			}
		} else if (content_type == CSV_CONTENT) {
			printf("%s%s%s%s", csv_data_enclosure, date_time, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_event->event_type == AE_HOST_ALERT) ? "主机警告" : "服务警告", csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, temp_host->name, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_event->event_type == AE_HOST_ALERT) ? "" : temp_service->description, csv_data_enclosure, csv_delimiter);
		} else {
			printf("<tr CLASS='data%s'>", (odd) ? "Even" : "Odd");

			printf("<td CLASS='data%s'>%s</td>", (odd) ? "Even" : "Odd", date_time);

			printf("<td CLASS='data%s'>%s</td>", (odd) ? "Even" : "Odd", (temp_event->event_type == AE_HOST_ALERT) ? "主机警告" : "服务警告");

			printf("<td CLASS='data%s'><a href='%s?type=%d&host=%s'>%s</a></td>", (odd) ? "Even" : "Odd", EXTINFO_CGI, DISPLAY_HOST_INFO, url_encode(temp_event->host_name), (temp_host->display_name != NULL) ? temp_host->display_name : temp_host->name);

			if (temp_event->event_type == AE_HOST_ALERT)
				printf("<td CLASS='data%s'>无</td>", (odd) ? "Even" : "Odd");
			else {
				printf("<td CLASS='data%s'><a href='%s?type=%d&host=%s", (odd) ? "Even" : "Odd", EXTINFO_CGI, DISPLAY_SERVICE_INFO, url_encode(temp_event->host_name));
				printf("&service=%s'>%s</a></td>", url_encode(temp_event->service_description), (temp_service->display_name != NULL) ? temp_service->display_name : temp_service->description);
			}

		}

		switch (temp_event->entry_type) {
		case AE_HOST_UP:
			status_bgclass = "hostUP";
			status = "运行";
			break;
		case AE_HOST_DOWN:
			status_bgclass = "hostDOWN";
			status = "宕机";
			break;
		case AE_HOST_UNREACHABLE:
			status_bgclass = "hostUNREACHABLE";
			status = "不可达";
			break;
		case AE_SERVICE_OK:
			status_bgclass = "serviceOK";
			status = "正常";
			break;
		case AE_SERVICE_WARNING:
			status_bgclass = "serviceWARNING";
			status = "警报";
			break;
		case AE_SERVICE_UNKNOWN:
			status_bgclass = "serviceUNKNOWN";
			status = "未知";
			break;
		case AE_SERVICE_CRITICAL:
			status_bgclass = "serviceCRITICAL";
			status = "紧急";
			break;
		default:
			status_bgclass = (odd) ? "Even" : "Odd";
			status = "???";
			break;
		}

		if (content_type == JSON_CONTENT) {
			printf("\"状态\": \"%s\", ", status);
			printf("\"状态类型\": \"%s\", ", (temp_event->state_type == AE_SOFT_STATE) ? "软件状态" : "硬件状态");
			printf("\"信息\": \"%s\"}", json_encode(temp_event->event_info));
		} else if (content_type == CSV_CONTENT) {
			printf("%s%s%s%s", csv_data_enclosure, status, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_event->state_type == AE_SOFT_STATE) ? "软件状态" : "硬件状态", csv_data_enclosure, csv_delimiter);
			printf("%s%s%s\n", csv_data_enclosure, temp_event->event_info, csv_data_enclosure);
		} else {
			printf("<td CLASS='%s'>%s</td>", status_bgclass, status);

			printf("<td CLASS='data%s'>%s</td>", (odd) ? "Even" : "Odd", (temp_event->state_type == AE_SOFT_STATE) ? "软件状态" : "硬件状态");

			printf("<td CLASS='data%s'>%s</td>", (odd) ? "Even" : "Odd", temp_event->event_info);

			printf("</tr>\n");
		}
	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT)
		printf("</TABLE>\n");
	else if (content_type == JSON_CONTENT)
		printf("\n]\n");


	return;
}

/* find a specific alert producer */
alert_producer *find_producer(int type, char *hname, char *sdesc) {
	alert_producer *temp_producer;

	for (temp_producer = producer_list; temp_producer != NULL; temp_producer = temp_producer->next) {

		if (temp_producer->producer_type != type)
			continue;
		if (hname != NULL && strcmp(hname, temp_producer->host_name))
			continue;
		if (sdesc != NULL && strcmp(sdesc, temp_producer->service_description))
			continue;

		return temp_producer;
	}

	return NULL;
}

/* adds a new producer to the list in memory */
alert_producer *add_producer(int producer_type, char *host_name, char *service_description) {
	alert_producer *new_producer = NULL;

	/* allocate memory for the new entry */
	new_producer = (alert_producer *)malloc(sizeof(alert_producer));
	if (new_producer == NULL)
		return NULL;

	/* allocate memory for the host name */
	if (host_name != NULL) {
		new_producer->host_name = (char *)malloc(strlen(host_name) + 1);
		if (new_producer->host_name != NULL)
			strcpy(new_producer->host_name, host_name);
	} else
		new_producer->host_name = NULL;

	/* allocate memory for the service description */
	if (service_description != NULL) {
		new_producer->service_description = (char *)malloc(strlen(service_description) + 1);
		if (new_producer->service_description != NULL)
			strcpy(new_producer->service_description, service_description);
	} else
		new_producer->service_description = NULL;

	new_producer->producer_type = producer_type;
	new_producer->total_alerts = 0;

	/* add the new entry to the list in memory, sorted by time */
	new_producer->next = producer_list;
	producer_list = new_producer;

	return new_producer;
}

void free_producer_list(void) {
	alert_producer *this_producer = NULL;
	alert_producer *next_producer = NULL;

	for (this_producer = producer_list; this_producer != NULL;) {
		next_producer = this_producer->next;
		if (this_producer->host_name != NULL)
			free(this_producer->host_name);
		if (this_producer->service_description != NULL)
			free(this_producer->service_description);
		free(this_producer);
		this_producer = next_producer;
	}

	producer_list = NULL;

	return;
}

/* displays top alerts */
void display_top_alerts(void) {
	archived_event *temp_event = NULL;
	alert_producer *temp_producer = NULL;
	alert_producer *next_producer = NULL;
	alert_producer *last_producer = NULL;
	alert_producer *new_producer = NULL;
	alert_producer *temp_list = NULL;
	host *temp_host;
	service *temp_service;
	int producer_type = AE_HOST_PRODUCER;
	int current_item = 0;
	int odd = 0;
	int json_start = TRUE;
	char *bgclass = "";

	/* process all events */
	for (temp_event = event_list; temp_event != NULL; temp_event = temp_event->next) {

		producer_type = (temp_event->event_type == AE_HOST_ALERT) ? AE_HOST_PRODUCER : AE_SERVICE_PRODUCER;

		/* see if we already have a record for the producer */
		temp_producer = find_producer(producer_type, temp_event->host_name, temp_event->service_description);

		/* if not, add a record */
		if (temp_producer == NULL)
			temp_producer = add_producer(producer_type, temp_event->host_name, temp_event->service_description);

		/* producer record could not be added */
		if (temp_producer == NULL)
			continue;

		/* update stats for producer */
		temp_producer->total_alerts++;
	}


	/* sort the producer list by total alerts (descending) */
	total_items = 0;
	temp_list = NULL;
	for (new_producer = producer_list; new_producer != NULL;) {
		next_producer = new_producer->next;

		last_producer = temp_list;
		for (temp_producer = temp_list; temp_producer != NULL; temp_producer = temp_producer->next) {
			if (new_producer->total_alerts >= temp_producer->total_alerts) {
				new_producer->next = temp_producer;
				if (temp_producer == temp_list)
					temp_list = new_producer;
				else
					last_producer->next = new_producer;
				break;
			} else
				last_producer = temp_producer;
		}

		if (temp_list == NULL) {
			new_producer->next = NULL;
			temp_list = new_producer;
		} else if (temp_producer == NULL) {
			new_producer->next = NULL;
			last_producer->next = new_producer;
		}

		new_producer = next_producer;
		total_items++;
	}
	producer_list = temp_list;


	if (content_type == JSON_CONTENT) {
		printf("\"警告排名\": [\n");
	} else if (content_type == CSV_CONTENT) {
		printf("%s序号%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s类型%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s主机%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s服务%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s警告总计%s\n", csv_data_enclosure, csv_data_enclosure);
	} else {
		printf("<BR>\n");

		if (item_limit <= 0 || total_items <= item_limit || total_items == 0)
			printf("<DIV ALIGN=CENTER CLASS='dataSubTitle'>显示所有%d匹配的警告\n", total_items);
		else
			printf("<DIV ALIGN=CENTER CLASS='dataSubTitle'>显示排名%d/%d匹配的警告\n", item_limit, total_items);

		printf("<TABLE BORDER=0 CLASS='data' align='center'>\n");

		printf("<TR><TD colspan='5'>");
		/* add export to csv, json, link */
		printf("<div class='csv_export_link'>");
		print_export_link(CSV_CONTENT, SUMMARY_CGI, NULL);
		print_export_link(JSON_CONTENT, SUMMARY_CGI, NULL);
		print_export_link(HTML_CONTENT, SUMMARY_CGI, NULL);
		printf("</div>\n");
		printf("</TD></TR>\n");

		printf("<TR><TH CLASS='data'>序号</TH><TH CLASS='data'>类型</TH><TH CLASS='data'>主机</TH><TH CLASS='data'>服务</TH><TH CLASS='data'>警告总计</TH></TR>\n");
	}


	/* display top producers */
	for (temp_producer = producer_list; temp_producer != NULL; temp_producer = temp_producer->next) {

		if (current_item >= item_limit && item_limit > 0 && content_type != CSV_CONTENT)
			break;

		current_item++;

		if (odd) {
			odd = 0;
			bgclass = "Odd";
		} else {
			odd = 1;
			bgclass = "Even";
		}

		if (content_type == JSON_CONTENT) {
			// always add a comma, except for the first line
			if (json_start == FALSE)
				printf(",\n");
			json_start = FALSE;
			printf("{ \"序号\": %d, ", current_item);
			printf(" \"产生类型\": \"%s\", ", (temp_producer->producer_type == AE_HOST_PRODUCER) ? "主机" : "服务");
			printf(" \"主机名称\": \"%s\", ", json_encode(temp_producer->host_name));

			temp_host = find_host(temp_producer->host_name);
			printf("\"主机显示名称\": \"%s\", ", (temp_host != NULL && temp_host->display_name != NULL) ? json_encode(temp_host->display_name) : json_encode(temp_host->name));
			if (temp_producer->producer_type == AE_HOST_PRODUCER) {
				printf(" \"服务描述\": null, ");
				printf(" \"服务显示名称\": null, ");
			} else {
				printf(" \"服务描述\": \"%s\", ", json_encode(temp_producer->service_description));

				temp_service = find_service(temp_producer->host_name, temp_producer->service_description);
				printf("\"服务显示名称\": \"%s\", ", (temp_service != NULL && temp_service->display_name != NULL) ? json_encode(temp_service->display_name) : json_encode(temp_service->description));
			}
			printf(" \"警告总计\": %d}", temp_producer->total_alerts);
		} else if (content_type == CSV_CONTENT) {
			printf("%s%d%s%s", csv_data_enclosure, current_item, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_producer->producer_type == AE_HOST_PRODUCER) ? "主机" : "服务", csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, temp_producer->host_name, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_producer->producer_type == AE_HOST_PRODUCER) ? "无" : temp_producer->service_description, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s\n", csv_data_enclosure, temp_producer->total_alerts, csv_data_enclosure);
		} else {
			printf("<tr CLASS='data%s'>", bgclass);

			printf("<td CLASS='data%s'>#%d</td>", bgclass, current_item);

			printf("<td CLASS='data%s'>%s</td>", bgclass, (temp_producer->producer_type == AE_HOST_PRODUCER) ? "主机" : "服务");

			printf("<td CLASS='data%s'><a href='%s?type=%d&host=%s'>%s</a></td>", bgclass, EXTINFO_CGI, DISPLAY_HOST_INFO, url_encode(temp_producer->host_name), temp_producer->host_name);

			if (temp_producer->producer_type == AE_HOST_PRODUCER)
				printf("<td CLASS='data%s'>无</td>", bgclass);
			else {
				printf("<td CLASS='data%s'><a href='%s?type=%d&host=%s", bgclass, EXTINFO_CGI, DISPLAY_SERVICE_INFO, url_encode(temp_producer->host_name));
				printf("&service=%s'>%s</a></td>", url_encode(temp_producer->service_description), temp_producer->service_description);
			}

			printf("<td CLASS='data%s'>%d</td>", bgclass, temp_producer->total_alerts);

			printf("</tr>\n");
		}
	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT)
		printf("</TABLE>\n");
	else if (content_type == JSON_CONTENT)
		printf("\n]\n");

	return;
}

/* displays alert totals */
void display_alerts(void) {
	int hard_host_up_alerts = 0;
	int soft_host_up_alerts = 0;
	int hard_host_down_alerts = 0;
	int soft_host_down_alerts = 0;
	int hard_host_unreachable_alerts = 0;
	int soft_host_unreachable_alerts = 0;
	int hard_service_ok_alerts = 0;
	int soft_service_ok_alerts = 0;
	int hard_service_warning_alerts = 0;
	int soft_service_warning_alerts = 0;
	int hard_service_unknown_alerts = 0;
	int soft_service_unknown_alerts = 0;
	int hard_service_critical_alerts = 0;
	int soft_service_critical_alerts = 0;
	int json_start = TRUE;
	archived_event *temp_event;
	host *temp_host;
	service *temp_service;

	if (display_type == REPORT_HOST_ALERT_TOTALS) {
		if (target_host == NULL)
			return;

		/* make sure the user is authorized to view this host */
		if (is_authorized_for_host(target_host, &current_authdata) == FALSE)
			return;

		if (show_all_hostgroups == FALSE && target_hostgroup != NULL) {
			if (is_host_member_of_hostgroup(target_hostgroup, target_host) == FALSE)
				return;
		}

		if (content_type == JSON_CONTENT) {
			if (json_list_start == FALSE)
				printf("],\n");
			json_list_start = FALSE;
			printf("\"主机名称\": \"%s\",\n", json_encode(target_host->name));
			printf("\"主机显示名称\": \"%s\", ", (target_host->display_name != NULL) ? json_encode(target_host->display_name) : json_encode(target_host->name));
			printf("\"报告\": [\n");
		}
	}

	if (display_type == REPORT_HOSTGROUP_ALERT_TOTALS) {
		if (target_hostgroup == NULL)
			return;

		/* make sure the user is authorized to view this hostgroup */
		if (is_authorized_for_hostgroup(target_hostgroup, &current_authdata) == FALSE)
			return;

		if (content_type == JSON_CONTENT) {
			if (json_list_start == FALSE)
				printf("],\n");
			json_list_start = FALSE;
			printf("\"主机组名称\": \"%s\",\n", json_encode(target_hostgroup->group_name));
			printf("\"报告\": [\n");
		}
	}
	if (display_type == REPORT_SERVICE_ALERT_TOTALS) {
		if (target_service == NULL)
			return;

		/* make sure the user is authorized to view this service */
		if (is_authorized_for_service(target_service, &current_authdata) == FALSE)
			return;

		if (show_all_hostgroups == FALSE && target_hostgroup != NULL) {
			temp_host = find_host(target_service->host_name);
			if (is_host_member_of_hostgroup(target_hostgroup, temp_host) == FALSE)
				return;
		}

		if (show_all_hosts == FALSE && target_host != NULL) {
			if (strcmp(target_host->name, target_service->host_name))
				return;
		}

		if (content_type == JSON_CONTENT) {
			if (json_list_start == FALSE)
				printf("],\n");
			json_list_start = FALSE;
			temp_host = find_host(target_service->host_name);
			if (temp_host == NULL)
				return;
			printf("\"主机名称\": \"%s\",\n", json_encode(temp_host->name));
			printf("\"主机显示名称\": \"%s\", ", (temp_host->display_name != NULL) ? json_encode(temp_host->display_name) : json_encode(temp_host->name));
			printf("\"服务描述\": \"%s\",\n", json_encode(target_service->description));
			printf("\"服务显示名称\": \"%s\", ", (target_service->display_name != NULL) ? json_encode(target_service->display_name) : json_encode(target_service->description));
			printf("\"报告\": [\n");
		}

	}

	if (display_type == REPORT_SERVICEGROUP_ALERT_TOTALS) {
		if (target_servicegroup == NULL)
			return;

		/* make sure the user is authorized to view this servicegroup */
		if (is_authorized_for_servicegroup(target_servicegroup, &current_authdata) == FALSE)
			return;

		if (content_type == JSON_CONTENT) {
			if (json_list_start == FALSE)
				printf("],\n");
			json_list_start = FALSE;
			printf("\"服务组名称\": \"%s\",\n", json_encode(target_servicegroup->group_name));
			printf("\"报告\": [\n");
		}
	}

	/* process all events */
	for (temp_event = event_list; temp_event != NULL; temp_event = temp_event->next) {

		if (display_type == REPORT_HOST_ALERT_TOTALS) {
			if (strcmp(temp_event->host_name, target_host->name))
				continue;
		}

		if (display_type == REPORT_HOSTGROUP_ALERT_TOTALS) {
			temp_host = find_host(temp_event->host_name);
			if (is_host_member_of_hostgroup(target_hostgroup, temp_host) == FALSE)
				continue;
		}

		if (display_type == REPORT_SERVICE_ALERT_TOTALS) {
			if (temp_event->event_type != AE_SERVICE_ALERT)
				continue;

			if (strcmp(temp_event->host_name, target_service->host_name) || strcmp(temp_event->service_description, target_service->description))
				continue;
		}

		if (display_type == REPORT_SERVICEGROUP_ALERT_TOTALS) {
			if (temp_event->event_type == AE_HOST_ALERT) {
				temp_host = find_host(temp_event->host_name);
				if (is_host_member_of_servicegroup(target_servicegroup, temp_host) == FALSE)
					continue;
			} else {
				temp_service = find_service(temp_event->host_name, temp_event->service_description);
				if (is_service_member_of_servicegroup(target_servicegroup, temp_service) == FALSE)
					continue;
			}
		}

		/* host alerts */
		if (temp_event->event_type == AE_HOST_ALERT) {
			if (temp_event->state_type == AE_SOFT_STATE) {
				if (temp_event->entry_type == AE_HOST_UP)
					soft_host_up_alerts++;
				else if (temp_event->entry_type == AE_HOST_DOWN)
					soft_host_down_alerts++;
				else if (temp_event->entry_type == AE_HOST_UNREACHABLE)
					soft_host_unreachable_alerts++;
			} else {
				if (temp_event->entry_type == AE_HOST_UP)
					hard_host_up_alerts++;
				else if (temp_event->entry_type == AE_HOST_DOWN)
					hard_host_down_alerts++;
				else if (temp_event->entry_type == AE_HOST_UNREACHABLE)
					hard_host_unreachable_alerts++;
			}
		}

		/* service alerts */
		else {
			if (temp_event->state_type == AE_SOFT_STATE) {
				if (temp_event->entry_type == AE_SERVICE_OK)
					soft_service_ok_alerts++;
				else if (temp_event->entry_type == AE_SERVICE_WARNING)
					soft_service_warning_alerts++;
				else if (temp_event->entry_type == AE_SERVICE_UNKNOWN)
					soft_service_unknown_alerts++;
				else if (temp_event->entry_type == AE_SERVICE_CRITICAL)
					soft_service_critical_alerts++;
			} else {
				if (temp_event->entry_type == AE_SERVICE_OK)
					hard_service_ok_alerts++;
				else if (temp_event->entry_type == AE_SERVICE_WARNING)
					hard_service_warning_alerts++;
				else if (temp_event->entry_type == AE_SERVICE_UNKNOWN)
					hard_service_unknown_alerts++;
				else if (temp_event->entry_type == AE_SERVICE_CRITICAL)
					hard_service_critical_alerts++;
			}
		}
	}


	if (content_type == JSON_CONTENT) {
		// always add a comma, except for the first line
		if (json_start == FALSE)
			printf(",\n");
		json_start = FALSE;

		/* Host Alerts Data */
		if (alert_types & AE_HOST_ALERT && display_type != REPORT_SERVICE_ALERT_TOTALS) {
			printf("{ \"主机运行软件状态\": %d, ", soft_host_up_alerts);
			printf("\"主机运行硬件状态\": %d, ", hard_host_up_alerts);
			printf("\"主机运行总计\": %d, ", soft_host_up_alerts + hard_host_up_alerts);
			printf("\"主机宕机软件状态\": %d, ", soft_host_down_alerts);
			printf("\"主机宕机硬件状态\": %d, ", hard_host_down_alerts);
			printf("\"主机宕机总计\": %d, ", soft_host_down_alerts + hard_host_down_alerts);
			printf("\"主机不可达软件状态\": %d, ", soft_host_unreachable_alerts);
			printf("\"主机不可达硬件状态\": %d, ", hard_host_unreachable_alerts);
			printf("\"主机不可达总计\": %d, ", soft_host_unreachable_alerts + hard_host_unreachable_alerts);
			printf("\"主机所有软件状态\": %d, ", soft_host_up_alerts + soft_host_down_alerts + soft_host_unreachable_alerts);
			printf("\"主机所有硬件状态\": %d, ", hard_host_up_alerts + hard_host_down_alerts + hard_host_unreachable_alerts);
			printf("\"主机所有总计\": %d", soft_host_up_alerts + hard_host_up_alerts + soft_host_down_alerts + hard_host_down_alerts + soft_host_unreachable_alerts + hard_host_unreachable_alerts);
		}

		/* Service Alerts Data */
		if (alert_types & AE_SERVICE_ALERT) {
			if (alert_types & AE_HOST_ALERT && display_type != REPORT_SERVICE_ALERT_TOTALS)
				printf(", ");
			else
				printf("{ ");

			printf("\"服务正常软件状态\": %d, ", soft_service_ok_alerts);
			printf("\"服务正常硬件状态\": %d, ", hard_service_ok_alerts);
			printf("\"服务正常总计\": %d, ", soft_service_ok_alerts + hard_service_ok_alerts);
			printf("\"服务警报软件状态\": %d, ", soft_service_warning_alerts);
			printf("\"服务警报硬件状态\": %d, ", hard_service_warning_alerts);
			printf("\"服务警报总计\": %d, ", soft_service_warning_alerts + hard_service_warning_alerts);
			printf("\"服务未知软件状态\": %d, ", soft_service_unknown_alerts);
			printf("\"务未知硬件状态\": %d, ", hard_service_unknown_alerts);
			printf("\"服务未知总计\": %d, ", soft_service_unknown_alerts + hard_service_unknown_alerts);
			printf("\"服务紧急软件状态\": %d, ", soft_service_critical_alerts);
			printf("\"服务紧急硬件状态\": %d, ", hard_service_critical_alerts);
			printf("\"服务紧急总计\": %d, ", soft_service_critical_alerts + hard_service_critical_alerts);
			printf("\"服务所有软件状态\": %d, ", soft_service_ok_alerts + soft_service_warning_alerts + soft_service_unknown_alerts + soft_service_critical_alerts);
			printf("\"服务所有硬件状态\": %d, ", hard_service_ok_alerts + hard_service_warning_alerts + hard_service_unknown_alerts + hard_service_critical_alerts);
			printf("\"服务所有总计\": %d}", soft_service_ok_alerts + soft_service_warning_alerts + soft_service_unknown_alerts + soft_service_critical_alerts + hard_service_ok_alerts + hard_service_warning_alerts + hard_service_unknown_alerts + hard_service_critical_alerts);
		} else {
			printf("}");
		}

	} else if (content_type == CSV_CONTENT) {
		if (display_type == REPORT_HOST_ALERT_TOTALS)
			printf("%s%s%s%s", csv_data_enclosure, target_host->name, csv_data_enclosure, csv_delimiter);
		if (display_type == REPORT_HOSTGROUP_ALERT_TOTALS)
			printf("%s%s%s%s", csv_data_enclosure, target_hostgroup->group_name, csv_data_enclosure, csv_delimiter);
		if (display_type == REPORT_SERVICE_ALERT_TOTALS) {
			printf("%s%s%s%s", csv_data_enclosure, target_service->host_name, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, target_service->description, csv_data_enclosure, csv_delimiter);
		}
		if (display_type == REPORT_SERVICEGROUP_ALERT_TOTALS)
			printf("%s%s%s%s", csv_data_enclosure, target_servicegroup->group_name, csv_data_enclosure, csv_delimiter);

		/* Host Alerts Data */
		if (alert_types & AE_HOST_ALERT && display_type != REPORT_SERVICE_ALERT_TOTALS) {
			printf("%s%d%s%s", csv_data_enclosure, soft_host_up_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, hard_host_up_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, soft_host_up_alerts + hard_host_up_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, soft_host_down_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, hard_host_down_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, soft_host_down_alerts + hard_host_down_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, soft_host_unreachable_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, hard_host_unreachable_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, soft_host_unreachable_alerts + hard_host_unreachable_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, soft_host_up_alerts + soft_host_down_alerts + soft_host_unreachable_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, hard_host_up_alerts + hard_host_down_alerts + hard_host_unreachable_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s", csv_data_enclosure, soft_host_up_alerts + hard_host_up_alerts + soft_host_down_alerts + hard_host_down_alerts + soft_host_unreachable_alerts + hard_host_unreachable_alerts, csv_data_enclosure);
		}

		/* Service Alerts Data */
		if (alert_types & AE_SERVICE_ALERT) {
			if (alert_types & AE_HOST_ALERT && display_type != REPORT_SERVICE_ALERT_TOTALS)
				printf("%s", csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, soft_service_ok_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, hard_service_ok_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, soft_service_ok_alerts + hard_service_ok_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, soft_service_warning_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, hard_service_warning_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, soft_service_warning_alerts + hard_service_warning_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, soft_service_unknown_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, hard_service_unknown_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, soft_service_unknown_alerts + hard_service_unknown_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, soft_service_critical_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, hard_service_critical_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, soft_service_critical_alerts + hard_service_critical_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, soft_service_ok_alerts + soft_service_warning_alerts + soft_service_unknown_alerts + soft_service_critical_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, hard_service_ok_alerts + hard_service_warning_alerts + hard_service_unknown_alerts + hard_service_critical_alerts, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s\n", csv_data_enclosure, soft_service_ok_alerts + soft_service_warning_alerts + soft_service_unknown_alerts + soft_service_critical_alerts + hard_service_ok_alerts + hard_service_warning_alerts + hard_service_unknown_alerts + hard_service_critical_alerts, csv_data_enclosure);
		} else {
			printf("\n");
		}
	} else {
		printf("<BR>\n");
		printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0 CLASS='reportDataEven'><TR><TD>\n");
		printf("<TABLE BORDER=0>\n");

		printf("<TR><TD COLSPAN=2 ALIGN=CENTER CLASS='dataSubTitle'>");
		if (display_type == REPORT_HOST_ALERT_TOTALS)
			printf("主机 '%s' (%s)", target_host->name, target_host->alias);

		if (display_type == REPORT_HOSTGROUP_ALERT_TOTALS)
			printf("主机组 '%s' (%s)", target_hostgroup->group_name, target_hostgroup->alias);

		if (display_type == REPORT_SERVICE_ALERT_TOTALS)
			printf("主机'%s'上的服务'%s'", target_service->host_name, target_service->description);

		if (display_type == REPORT_SERVICEGROUP_ALERT_TOTALS)
			printf("服务组 '%s' (%s)", target_servicegroup->group_name, target_servicegroup->alias);
		printf("</TD></TR>\n");

		printf("<TR>\n");

		if (alert_types & AE_HOST_ALERT && display_type != REPORT_SERVICE_ALERT_TOTALS) {

			printf("<TD ALIGN=CENTER VALIGN=TOP>\n");

			printf("<DIV ALIGN=CENTER CLASS='dataSubTitle'>主机警告</DIV>\n");

			printf("<DIV ALIGN=CENTER>\n");
			printf("<TABLE BORDER=0 CLASS='data'>\n");
			printf("<TR><TH CLASS='data'>状态</TH><TH CLASS='data'>软件警告</TH><TH CLASS='data'>硬件警告</TH><TH CLASS='data'>警告总计</TH></TR>\n");

			printf("<TR CLASS='dataOdd'><TD CLASS='hostUP'>运行</TD><TD CLASS='dataOdd'>%d</TD><TD CLASS='dataOdd'>%d</TD><TD CLASS='dataOdd'>%d</TD></TR>\n", soft_host_up_alerts, hard_host_up_alerts, soft_host_up_alerts + hard_host_up_alerts);
			printf("<TR CLASS='dataEven'><TD CLASS='hostDOWN'>宕机</TD><TD CLASS='dataEven'>%d</TD><TD CLASS='dataEven'>%d</TD><TD CLASS='dataEven'>%d</TD></TR>\n", soft_host_down_alerts, hard_host_down_alerts, soft_host_down_alerts + hard_host_down_alerts);
			printf("<TR CLASS='dataOdd'><TD CLASS='hostUNREACHABLE'>不可达</TD><TD CLASS='dataOdd'>%d</TD><TD CLASS='dataOdd'>%d</TD><TD CLASS='dataOdd'>%d</TD></TR>\n", soft_host_unreachable_alerts, hard_host_unreachable_alerts, soft_host_unreachable_alerts + hard_host_unreachable_alerts);
			printf("<TR CLASS='dataEven'><TD CLASS='dataEven'>所有状态</TD><TD CLASS='dataEven'>%d</TD><TD CLASS='dataEven'>%d</TD><TD CLASS='dataEven'><B>%d</B></TD></TR>\n", soft_host_up_alerts + soft_host_down_alerts + soft_host_unreachable_alerts, hard_host_up_alerts + hard_host_down_alerts + hard_host_unreachable_alerts, soft_host_up_alerts + hard_host_up_alerts + soft_host_down_alerts + hard_host_down_alerts + soft_host_unreachable_alerts + hard_host_unreachable_alerts);

			printf("</TABLE>\n");
			printf("</DIV>\n");

			printf("</TD>\n");
		}

		if (alert_types & AE_SERVICE_ALERT) {

			printf("<TD ALIGN=CENTER VALIGN=TOP>\n");

			printf("<DIV ALIGN=CENTER CLASS='dataSubTitle'>服务警告</DIV>\n");

			printf("<DIV ALIGN=CENTER>\n");
			printf("<TABLE BORDER=0 CLASS='data'>\n");
			printf("<TR><TH CLASS='data'>>状态</TH><TH CLASS='data'>软件警告</TH><TH CLASS='data'>硬件警告</TH><TH CLASS='data'>警告总计</TH></TR>\n");

			printf("<TR CLASS='dataOdd'><TD CLASS='serviceOK'>正常</TD><TD CLASS='dataOdd'>%d</TD><TD CLASS='dataOdd'>%d</TD><TD CLASS='dataOdd'>%d</TD></TR>\n", soft_service_ok_alerts, hard_service_ok_alerts, soft_service_ok_alerts + hard_service_ok_alerts);
			printf("<TR CLASS='dataEven'><TD CLASS='serviceWARNING'>警报</TD><TD CLASS='dataEven'>%d</TD><TD CLASS='dataEven'>%d</TD><TD CLASS='dataEven'>%d</TD></TR>\n", soft_service_warning_alerts, hard_service_warning_alerts, soft_service_warning_alerts + hard_service_warning_alerts);
			printf("<TR CLASS='dataOdd'><TD CLASS='serviceUNKNOWN'>未知</TD><TD CLASS='dataOdd'>%d</TD><TD CLASS='dataOdd'>%d</TD><TD CLASS='dataOdd'>%d</TD></TR>\n", soft_service_unknown_alerts, hard_service_unknown_alerts, soft_service_unknown_alerts + hard_service_unknown_alerts);
			printf("<TR CLASS='dataEven'><TD CLASS='serviceCRITICAL'>紧急</TD><TD CLASS='dataEven'>%d</TD><TD CLASS='dataEven'>%d</TD><TD CLASS='dataEven'>%d</TD></TR>\n", soft_service_critical_alerts, hard_service_critical_alerts, soft_service_critical_alerts + hard_service_critical_alerts);
			printf("<TR CLASS='dataOdd'><TD CLASS='dataOdd'>所有状态</TD><TD CLASS='dataOdd'>%d</TD><TD CLASS='dataOdd'>%d</TD><TD CLASS='dataOdd'><B>%d</B></TD></TR>\n", soft_service_ok_alerts + soft_service_warning_alerts + soft_service_unknown_alerts + soft_service_critical_alerts, hard_service_ok_alerts + hard_service_warning_alerts + hard_service_unknown_alerts + hard_service_critical_alerts, soft_service_ok_alerts + soft_service_warning_alerts + soft_service_unknown_alerts + soft_service_critical_alerts + hard_service_ok_alerts + hard_service_warning_alerts + hard_service_unknown_alerts + hard_service_critical_alerts);

			printf("</TABLE>\n");
			printf("</DIV>\n");

			printf("</TD>\n");
		}

		printf("</TR>\n");

		printf("</TABLE>\n");
		printf("</TD></TR></TABLE>\n");
	}

	return;
}