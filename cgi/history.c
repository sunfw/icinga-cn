/*****************************************************************************
 *
 * HISTORY.C - Icinga History CGI
 *
 * Copyright (c) 1999-2009 Ethan Galstad (egalstad@nagios.org)
 * Copyright (c) 2009-2013 Icinga Development Team (http://www.icinga.org)
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
 *
 *****************************************************************************/

/** @file history.c
 *  @brief cgi to browse through log history of a host/service
**/

#include "../include/config.h"
#include "../include/common.h"
#include "../include/objects.h"

#include "../include/getcgi.h"
#include "../include/cgiutils.h"
#include "../include/cgiauth.h"
#include "../include/readlogs.h"


/** @name External vars
    @{ **/
extern char main_config_file[MAX_FILENAME_LENGTH];
extern char url_images_path[MAX_FILENAME_LENGTH];

extern int enable_splunk_integration;
extern int embedded;
extern int display_header;
extern int daemon_check;
extern int result_limit;
extern int show_partial_hostgroups;
/** @} */

/** @name Internal vars
    @{ **/
int display_type = DISPLAY_HOSTS;			/**< determine the view (host/service) */
int show_all_hosts = TRUE;			/**< if historical data is requested for all hosts */
int reverse = FALSE;				/**< determine if log should be viewed in reverse order */
int history_options = HISTORY_ALL;		/**< determines the type of historical data */
int state_options = STATE_ALL;			/**< the state of historical data */
int result_start = 1;				/**< keep track from where we have to start displaying results */
int get_result_limit = -1;			/**< needed to overwrite config value with result_limit we get vie GET */

int display_frills = TRUE;			/**< determine if icons should be shown in listing */
int display_timebreaks = TRUE;			/**< determine if time breaks should be shown */
int display_system_messages = TRUE;		/**< determine if system messages should be shown */
int display_flapping_alerts = TRUE;		/**< determine if flapping alerts should be shown */
int display_downtime_alerts = TRUE;		/**< determine if downtime alerts should be shown */

char *host_name = "all";				/**< the requested host name */
char *service_desc = "";				/**< the requested service name */
char *hostgroup_name = "";				/**< the requested hostgroup name */
char *servicegroup_name = "";				/**< the requested hostgroup name */

time_t ts_start = 0L;				/**< start time as unix timestamp */
time_t ts_end = 0L;				/**< end time as unix timestamp */

authdata current_authdata;			/**< struct to hold current authentication data */

int CGI_ID = HISTORY_CGI_ID;			/**< ID to identify the cgi for functions in cgiutils.c */
/** @} */

/** @brief displays the requested historical log entries
 *
 * Applies the requested filters, reads in all necessary log files
 * and afterwards showing each log entry.
**/
void show_history(void);

/** @brief Parses the requested GET/POST variables
 *  @return wether parsing was successful or not
 *	@retval TRUE
 *	@retval FALSE
 *
 *  @n This function parses the request and set's the necessary variables
**/
int process_cgivars(void);

/** @brief Yes we need a main function **/
int main(void) {
	int result = OK;

	/* get the variables passed to us */
	process_cgivars();

	/* reset internal CGI variables */
	reset_cgi_vars();

	/* read the CGI configuration file */
	result = read_cgi_config_file(get_cgi_config_location());
	if (result == ERROR) {
		document_header(CGI_ID, FALSE, "错误");
		print_error(get_cgi_config_location(), ERROR_CGI_CFG_FILE, FALSE);
		document_footer(CGI_ID);
		return ERROR;
	}

	/* read the main configuration file */
	result = read_main_config_file(main_config_file);
	if (result == ERROR) {
		document_header(CGI_ID, FALSE, "错误");
		print_error(main_config_file, ERROR_CGI_MAIN_CFG, FALSE);
		document_footer(CGI_ID);
		return ERROR;
	}

	/* read all object configuration data */
	result = read_all_object_configuration_data(main_config_file, READ_ALL_OBJECT_DATA);
	if (result == ERROR) {
		document_header(CGI_ID, FALSE, "错误");
		print_error(NULL, ERROR_CGI_OBJECT_DATA, FALSE);
		document_footer(CGI_ID);
		return ERROR;
	}

	/* overwrite config value with amount we got via GET */
	result_limit = (get_result_limit != -1) ? get_result_limit : result_limit;

	document_header(CGI_ID, TRUE, "历史");

	/* get authentication information */
	get_authentication_information(&current_authdata);

	/* calculate timestamps for reading logs */
	convert_timeperiod_to_times(TIMEPERIOD_SINGLE_DAY, &ts_start, &ts_end);

	if (display_header == TRUE) {

		/* begin top table */
		printf("<table border=0 width=100%%>\n");
		printf("<tr>\n");

		/* left column of the first row */
		printf("<td align=left valign=top width=33%%>\n");

		if (display_type == DISPLAY_HOSTS)
			display_info_table("主机警告历史", &current_authdata, daemon_check);
		else if (display_type == DISPLAY_SERVICES)
			display_info_table("服务警告历史", &current_authdata, daemon_check);
		else if (display_type == DISPLAY_HOSTGROUPS)
			display_info_table("主机组警告历史", &current_authdata, daemon_check);
		else if (display_type == DISPLAY_SERVICEGROUPS)
			display_info_table("服务组警告历史", &current_authdata, daemon_check);
		else
			display_info_table("警告历史", &current_authdata, daemon_check);

		printf("<TABLE BORDER=1 CELLPADDING=0 CELLSPACING=0 CLASS='linkBox'>\n");
		printf("<TR><TD CLASS='linkBox'>\n");
		if (display_type == DISPLAY_HOSTS) {
			printf("<a href='%s?host=%s'>查看%s服务状态详情</a><br>\n", STATUS_CGI, (show_all_hosts == TRUE) ? "all" : url_encode(host_name), (show_all_hosts == TRUE) ? "所有主机" : "该主机");
			printf("<a href='%s?host=%s'>查看%s通知</a><br>\n", NOTIFICATIONS_CGI, (show_all_hosts == TRUE) ? "all" : url_encode(host_name), (show_all_hosts == TRUE) ? "所有主机" : "该主机");
			printf("<a href='%s?type=%d&host=%s'>查看该主机信息</a><br>\n", EXTINFO_CGI, DISPLAY_HOST_INFO, url_encode(host_name));
#ifdef USE_TRENDS
			if (show_all_hosts == FALSE)
				printf("<a href='%s?host=%s'>查看该主机趋势</a>\n", TRENDS_CGI, url_encode(host_name));
#endif
		} else if (display_type == DISPLAY_SERVICES) {
			printf("<a href='%s?host=%s&service=%s'>查看该服务通知</a><br>\n", NOTIFICATIONS_CGI, url_encode(host_name), url_encode(service_desc));
			printf("<a href='%s?type=%d&host=%s&service=%s'>查看该服务信息</a><br>\n", EXTINFO_CGI, DISPLAY_SERVICE_INFO, url_encode(host_name), url_encode(service_desc));
#ifdef USE_TRENDS
			printf("<a href='%s?host=%s&service=%s'>查看该服务趋势</a><br>\n", TRENDS_CGI, url_encode(host_name), url_encode(service_desc));
#endif
			printf("<a href='%s?host=%s'>查看该主机警告历史</a>\n", HISTORY_CGI, url_encode(host_name));
		} else if (display_type == DISPLAY_HOSTGROUPS) {
			printf("<a href='%s?hostgroup=%s&style=hostdetail'>查看该主机组主机状态详情</a><br>\n", STATUS_CGI, url_encode(hostgroup_name));
			printf("<a href='%s?hostgroup=%s&style=detail'>查看该主机组服务状态详情</a><br>\n", STATUS_CGI, url_encode(hostgroup_name));
			printf("<a href='%s?hostgroup=%s'查看该主机组通知</a>\n", NOTIFICATIONS_CGI, url_encode(hostgroup_name));
		} else if (display_type == DISPLAY_SERVICEGROUPS) {
			printf("<a href='%s?servicegroup=%s&style=hostdetail'>查看该服务组主机状态详情</a><br>\n", STATUS_CGI, url_encode(servicegroup_name));
			printf("<a href='%s?servicegroup=%s&style=detail'>查看该服务组服务状态详情</a><br>\n", STATUS_CGI, url_encode(servicegroup_name));
			printf("<a href='%s?servicegroup=%s'>查看该服务组通知</a>\n", NOTIFICATIONS_CGI, url_encode(servicegroup_name));
		}
		printf("</TD></TR>\n");
		printf("</TABLE>\n");

		printf("</td>\n");

		/* middle column of top row */
		printf("<td align=center valign=top width=33%%>\n");

		printf("<DIV ALIGN=CENTER CLASS='dataTitle'>\n");
		if (display_type == DISPLAY_SERVICES)
			printf("主机'%s'上的服务'%s'", html_encode(host_name, TRUE), html_encode(service_desc, TRUE));
		else if (display_type == DISPLAY_HOSTS) {
			if (show_all_hosts == TRUE)
				printf("所有主机和服务");
			else
				printf("主机'%s'", html_encode(host_name, TRUE));
		} else if (display_type == DISPLAY_HOSTGROUPS)
			printf("主机组'%s'", html_encode(hostgroup_name, TRUE));
		else if (display_type == DISPLAY_SERVICEGROUPS)
			printf("服务组'%s'", html_encode(servicegroup_name, TRUE));
		printf("</DIV>\n");
		printf("<BR />\n");

		display_nav_table(ts_start, ts_end);

		printf("</td>\n");

		/* right hand column of top row */
		printf("<td align=right valign=top width=33%%>\n");

		printf("<form method=\"GET\" action=\"%s\">\n", HISTORY_CGI);
		printf("<input type='hidden' name='ts_start' value='%lu'>\n", ts_start);
		printf("<input type='hidden' name='ts_end' value='%lu'>\n", ts_end);
		printf("<input type='hidden' name='limit' value='%d'>\n", result_limit);

		if (display_type == DISPLAY_HOSTGROUPS)
			printf("<input type='hidden' name='hostgroup' value='%s'>\n", escape_string(hostgroup_name));
		else if (display_type == DISPLAY_SERVICEGROUPS)
			printf("<input type='hidden' name='servicegroup' value='%s'>\n", escape_string(servicegroup_name));
		else {
			printf("<input type='hidden' name='host' value='%s'>\n", (show_all_hosts == TRUE) ? "all" : escape_string(host_name));
			if (display_type == DISPLAY_SERVICES)
				printf("<input type='hidden' name='service' value='%s'>\n", escape_string(service_desc));
		}
		printf("<table border=0 CLASS='optBox'>\n");

		printf("<tr>\n");
		printf("<td align=left CLASS='optBoxItem'>状态类型选项:</td>\n");
		printf("</tr>\n");

		printf("<tr>\n");
		printf("<td align=left CLASS='optBoxItem'><select name='statetype'>\n");
		printf("<option value=%d %s>所有状态类型</option>\n", STATE_ALL, (state_options == STATE_ALL) ? "selected" : "");
		printf("<option value=%d %s>软件状态</option>\n", STATE_SOFT, (state_options == STATE_SOFT) ? "selected" : "");
		printf("<option value=%d %s>硬件状态</option>\n", STATE_HARD, (state_options == STATE_HARD) ? "selected" : "");
		printf("</select></td>\n");
		printf("</tr>\n");

		printf("<tr>\n");
		printf("<td align=left CLASS='optBoxItem'>");
		if (display_type == DISPLAY_HOSTGROUPS || display_type == DISPLAY_SERVICEGROUPS)
			printf("该%s组", (display_type == DISPLAY_HOSTGROUPS) ? "主机" : "服务");
		else if (display_type == DISPLAY_HOSTS)
			printf("%s主机%s", (show_all_hosts == TRUE) ? "所有" : "该", (show_all_hosts == TRUE) ? "" : "");
		else
			printf("服务");
        	printf("历史详情级别");
		printf(":</td>\n");
		printf("</tr>\n");
		printf("<tr>\n");
		printf("<td align=left CLASS='optBoxItem'><select name='type'>\n");
		if (display_type == DISPLAY_HOSTS || display_type == DISPLAY_HOSTGROUPS)
			printf("<option value=%d %s>所有警告</option>\n", HISTORY_ALL, (history_options == HISTORY_ALL) ? "selected" : "");
		printf("<option value=%d %s>所有服务警告</option>\n", HISTORY_SERVICE_ALL, (history_options == HISTORY_SERVICE_ALL) ? "selected" : "");
		if (display_type == DISPLAY_HOSTS || display_type == DISPLAY_HOSTGROUPS)
			printf("<option value=%d %s>所有主机警告</option>\n", HISTORY_HOST_ALL, (history_options == HISTORY_HOST_ALL) ? "selected" : "");
		printf("<option value=%d %s>服务警报</option>\n", HISTORY_SERVICE_WARNING, (history_options == HISTORY_SERVICE_WARNING) ? "selected" : "");
		printf("<option value=%d %s>服务未知</option>\n", HISTORY_SERVICE_UNKNOWN, (history_options == HISTORY_SERVICE_UNKNOWN) ? "selected" : "");
		printf("<option value=%d %s>服务严重</option>\n", HISTORY_SERVICE_CRITICAL, (history_options == HISTORY_SERVICE_CRITICAL) ? "selected" : "");
		printf("<option value=%d %s>服务恢复</option>\n", HISTORY_SERVICE_RECOVERY, (history_options == HISTORY_SERVICE_RECOVERY) ? "selected" : "");
		if (display_type == DISPLAY_HOSTS || display_type == DISPLAY_HOSTGROUPS) {
			printf("<option value=%d %s>主机宕机</option>\n", HISTORY_HOST_DOWN, (history_options == HISTORY_HOST_DOWN) ? "selected" : "");
			printf("<option value=%d %s>主机不可达</option>\n", HISTORY_HOST_UNREACHABLE, (history_options == HISTORY_HOST_UNREACHABLE) ? "selected" : "");
			printf("<option value=%d %s>主机恢复</option>\n", HISTORY_HOST_RECOVERY, (history_options == HISTORY_HOST_RECOVERY) ? "selected" : "");
		}
		printf("</select></td>\n");
		printf("</tr>\n");

		printf("<tr>\n");
		printf("<td align=left valign=bottom CLASS='optBoxItem'><input type='checkbox' name='noflapping' %s> 隐藏抖动警告</td>", (display_flapping_alerts == FALSE) ? "checked" : "");
		printf("</tr>\n");
		printf("<tr>\n");
		printf("<td align=left valign=bottom CLASS='optBoxItem'><input type='checkbox' name='nodowntime' %s> 隐藏宕机警告</td>", (display_downtime_alerts == FALSE) ? "checked" : "");
		printf("</tr>\n");

		printf("<tr>\n");
		printf("<td align=left valign=bottom CLASS='optBoxItem'><input type='checkbox' name='nosystem' %s> 隐藏进程消息</td>", (display_system_messages == FALSE) ? "checked" : "");
		printf("</tr>\n");
		printf("<tr>\n");
		printf("<td align=left valign=bottom CLASS='optBoxItem'><input type='checkbox' name='order' value='old2new' %s> 旧的数据条目优先</td>", (reverse == TRUE) ? "checked" : "");
		printf("</tr>\n");

		printf("<tr>\n");
		printf("<td align=left CLASS='optBoxItem'><input type='submit' value='更新'></td>\n");
		printf("</tr>\n");

		printf("</table>\n");
		printf("</form>\n");
		printf("</td>\n");

		/* end of top table */
		printf("</tr>\n");
		printf("</table>\n");

	}

	/* display history */
	show_history();

	document_footer(CGI_ID);

	/* free allocated memory */
	free_memory();

	return OK;
}

int process_cgivars(void) {
	char **variables;
	int error = FALSE;
	int x;

	variables = getcgivars();

	for (x = 0; variables[x] != NULL; x++) {

		/* do some basic length checking on the variable identifier to prevent buffer overflows */
		if (strlen(variables[x]) >= MAX_INPUT_BUFFER - 1)
			continue;

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

			display_type = DISPLAY_HOSTS;

			if (!strcmp(host_name, "all"))
				show_all_hosts = TRUE;
			else
				show_all_hosts = FALSE;
		}

		/* we found the service argument */
		else if (!strcmp(variables[x], "service")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if ((service_desc = (char *)strdup(variables[x])) == NULL)
				service_desc = "";
			strip_html_brackets(service_desc);

			display_type = DISPLAY_SERVICES;
		}

		/* we found the hostgroup argument */
		else if (!strcmp(variables[x], "hostgroup")) {
			display_type = DISPLAY_HOSTGROUPS;
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}
			if ((hostgroup_name = strdup(variables[x])) == NULL)
				hostgroup_name = "";
			strip_html_brackets(hostgroup_name);
		}

		/* we found the servicegroup argument */
		else if (!strcmp(variables[x], "servicegroup")) {
			display_type = DISPLAY_SERVICEGROUPS;
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}
			if ((servicegroup_name = strdup(variables[x])) == NULL)
				servicegroup_name = "";
			strip_html_brackets(servicegroup_name);
		}

		/* we found the history type argument */
		else if (!strcmp(variables[x], "type")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			history_options = atoi(variables[x]);
		}

		/* we found the history state type argument */
		else if (!strcmp(variables[x], "statetype")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			state_options = atoi(variables[x]);
		}

		/* we found first time argument */
		else if (!strcmp(variables[x], "ts_start")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			ts_start = (time_t)strtoul(variables[x], NULL, 10);
		}

		/* we found last time argument */
		else if (!strcmp(variables[x], "ts_end")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			ts_end = (time_t)strtoul(variables[x], NULL, 10);
		}

		/* we found the order argument */
		else if (!strcmp(variables[x], "order")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (!strcmp(variables[x], "new2old"))
				reverse = FALSE;
			else if (!strcmp(variables[x], "old2new"))
				reverse = TRUE;
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

		/* we found the nofrills option */
		else if (!strcmp(variables[x], "nofrills"))
			display_frills = FALSE;

		/* we found the notimebreaks option */
		else if (!strcmp(variables[x], "notimebreaks"))
			display_timebreaks = FALSE;

		/* we found the no system messages option */
		else if (!strcmp(variables[x], "nosystem"))
			display_system_messages = FALSE;

		/* we found the no flapping alerts option */
		else if (!strcmp(variables[x], "noflapping"))
			display_flapping_alerts = FALSE;

		/* we found the no downtime alerts option */
		else if (!strcmp(variables[x], "nodowntime"))
			display_downtime_alerts = FALSE;

		/* start num results to skip on displaying statusdata */
		else if (!strcmp(variables[x], "start")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			result_start = atoi(variables[x]);

			if (result_start < 1)
				result_start = 1;
		}

		/* amount of results to display */
		else if (!strcmp(variables[x], "limit")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			get_result_limit = atoi(variables[x]);
		}
	}

	/* free memory allocated to the CGI variables */
	free_cgivars(variables);

	return error;
}

void show_history(void) {
	char image[MAX_INPUT_BUFFER];
	char image_alt[MAX_INPUT_BUFFER];
	char match1[MAX_INPUT_BUFFER];
	char match2[MAX_INPUT_BUFFER];
	char date_time[MAX_DATETIME_LENGTH];
	char last_message_date[MAX_INPUT_BUFFER] = "";
	char current_message_date[MAX_INPUT_BUFFER] = "";
	char *temp_buffer = NULL;
	char *entry_host_name = NULL;
	char *entry_service_desc = NULL;
	char *error_text = NULL;
	int system_message = FALSE;
	int display_line = FALSE;
	int history_type = SERVICE_HISTORY;
	int history_detail_type = HISTORY_SERVICE_CRITICAL;
	int status = READLOG_OK;
	int displayed_entries = 0;
	int total_entries = 0;
	time_t t; //
	host *temp_host = NULL;
	service *temp_service = NULL;
	hostgroup *temp_hostgroup = NULL;
	servicegroup *temp_servicegroup = NULL;
	logentry *temp_entry = NULL;
	struct tm *time_ptr = NULL;
	logentry *entry_list = NULL;
	logfilter *filter_list = NULL;


	if (display_type == DISPLAY_HOSTGROUPS) {

		temp_hostgroup = find_hostgroup(hostgroup_name);

		if (temp_hostgroup == NULL) {
			print_generic_error_message("没有使用该名称定义的主机组.", NULL, 0);
			return;
		}
		/* make sure the user is authorized to view this hostgroup */
		if (show_partial_hostgroups == FALSE && is_authorized_for_hostgroup(temp_hostgroup, &current_authdata) == FALSE) {
			print_generic_error_message("很显然您没有权限查看所请求主机组的信息...", "如果您认为这是一个错误, 请检查访问CGI的HTTP服务器身份验证要求,并检查您的CGI配置文件的授权选项.", 0);
			return;
		}
	}

	if (display_type == DISPLAY_SERVICEGROUPS) {

		temp_servicegroup = find_servicegroup(servicegroup_name);

		if (temp_servicegroup == NULL) {
			print_generic_error_message("没有使用该名称定义的服务组.", NULL, 0);
			return;
		}
		/* make sure the user is authorized to view this servicegroup */
		if (is_authorized_for_servicegroup(temp_servicegroup, &current_authdata) == FALSE) {
			print_generic_error_message("很显然您没有权限查看所请求服务组的信息...", "如果您认为这是一个错误, 请检查访问CGI的HTTP服务器身份验证要求,并检查您的CGI配置文件的授权选项.", 0);
			return;
		}
	}

	add_log_filter(&filter_list, LOGENTRY_SERVICE_CRITICAL, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_SERVICE_WARNING, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_SERVICE_UNKNOWN, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_SERVICE_RECOVERY, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_SERVICE_OK, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_SERVICE_FLAPPING_STARTED, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_SERVICE_FLAPPING_STOPPED, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_SERVICE_FLAPPING_DISABLED, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_SERVICE_DOWNTIME_STARTED, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_SERVICE_DOWNTIME_STOPPED, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_SERVICE_DOWNTIME_CANCELLED, LOGFILTER_INCLUDE);

	if (display_type == DISPLAY_HOSTS || display_type == DISPLAY_HOSTGROUPS) {
		add_log_filter(&filter_list, LOGENTRY_HOST_DOWN, LOGFILTER_INCLUDE);
		add_log_filter(&filter_list, LOGENTRY_HOST_UNREACHABLE, LOGFILTER_INCLUDE);
		add_log_filter(&filter_list, LOGENTRY_HOST_RECOVERY, LOGFILTER_INCLUDE);
		add_log_filter(&filter_list, LOGENTRY_HOST_UP, LOGFILTER_INCLUDE);
		add_log_filter(&filter_list, LOGENTRY_HOST_FLAPPING_STARTED, LOGFILTER_INCLUDE);
		add_log_filter(&filter_list, LOGENTRY_HOST_FLAPPING_STOPPED, LOGFILTER_INCLUDE);
		add_log_filter(&filter_list, LOGENTRY_HOST_FLAPPING_DISABLED, LOGFILTER_INCLUDE);
		add_log_filter(&filter_list, LOGENTRY_HOST_FLAPPING_DISABLED, LOGFILTER_INCLUDE);
		add_log_filter(&filter_list, LOGENTRY_HOST_FLAPPING_STOPPED, LOGFILTER_INCLUDE);
		add_log_filter(&filter_list, LOGENTRY_HOST_FLAPPING_DISABLED, LOGFILTER_INCLUDE);
	}

	/* system log entries */
	add_log_filter(&filter_list, LOGENTRY_STARTUP, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_SHUTDOWN, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_BAILOUT, LOGFILTER_INCLUDE);
	add_log_filter(&filter_list, LOGENTRY_RESTART, LOGFILTER_INCLUDE);


	/* scan the log file for archived state data */
	status = get_log_entries(&entry_list, &filter_list, &error_text, NULL, reverse, ts_start, ts_end);


	/* dealing with errors */
	if (status == READLOG_ERROR_WARNING) {
		if (error_text != NULL) {
			print_generic_error_message(error_text, NULL, 0);
			my_free(error_text);
		} else
			print_generic_error_message("未知错误", NULL, 0);
	}

	if (status == READLOG_ERROR_MEMORY)
			print_generic_error_message("内存溢出…","显示所有我能获取的!", 0);


	if (status == READLOG_ERROR_FATAL) {
		if (error_text != NULL) {
			print_generic_error_message(error_text, NULL, 0);
			my_free(error_text);
		}

		return;

	/* now we start displaying the log entries */
	} else {

		printf("<table width='100%%' cellspacing=0 cellpadding=0><tr><td width='33%%'></td><td width='33%%' nowrap>");
		printf("<div class='page_selector' id='hist_page_selector'>\n");
		printf("<div id='page_navigation_copy'></div>");
		page_limit_selector(result_start);
		printf("</div>\n");
		printf("</td><td width='33%%' align='right' style='padding-right:2px'>\n");
		print_export_link(HTML_CONTENT, HISTORY_CGI, NULL);
		printf("</td></tr></table>");

		printf("<DIV CLASS='logEntries'>\n");

		for (temp_entry = entry_list; temp_entry != NULL; temp_entry = temp_entry->next) {

			strcpy(image, "");
			strcpy(image_alt, "");
			system_message = FALSE;

			switch (temp_entry->type) {

				/* service state alerts */
			case LOGENTRY_SERVICE_CRITICAL:
			case LOGENTRY_SERVICE_WARNING:
			case LOGENTRY_SERVICE_UNKNOWN:
			case LOGENTRY_SERVICE_RECOVERY:
			case LOGENTRY_SERVICE_OK:

				history_type = SERVICE_HISTORY;

				/* get host and service names */
				temp_buffer = my_strtok(temp_entry->entry_text, ":");
				temp_buffer = my_strtok(NULL, ";");
				if (temp_buffer)
					entry_host_name = strdup(temp_buffer + 1);
				else
					entry_host_name = NULL;

				temp_buffer = my_strtok(NULL, ";");
				if (temp_buffer)
					entry_service_desc = strdup(temp_buffer);
				else
					entry_service_desc = NULL;

				if (temp_entry->type == LOGENTRY_SERVICE_CRITICAL) {
					strcpy(image, CRITICAL_ICON);
					strcpy(image_alt, "严重");
					history_detail_type = HISTORY_SERVICE_CRITICAL;
				} else if (temp_entry->type == LOGENTRY_SERVICE_WARNING) {
					strcpy(image, WARNING_ICON);
					strcpy(image_alt, "警报");
					history_detail_type = HISTORY_SERVICE_WARNING;
				} else if (temp_entry->type == LOGENTRY_SERVICE_UNKNOWN) {
					strcpy(image, UNKNOWN_ICON);
					strcpy(image_alt, "未知");
					history_detail_type = HISTORY_SERVICE_UNKNOWN;
				} else if (temp_entry->type == LOGENTRY_SERVICE_RECOVERY || temp_entry->type == LOGENTRY_SERVICE_OK) {
					strcpy(image, OK_ICON);
					strcpy(image_alt, "正常");
					history_detail_type = HISTORY_SERVICE_RECOVERY;
				}
				break;

				/* service flapping alerts */
			case LOGENTRY_SERVICE_FLAPPING_STARTED:
			case LOGENTRY_SERVICE_FLAPPING_STOPPED:
			case LOGENTRY_SERVICE_FLAPPING_DISABLED:

				if (display_flapping_alerts == FALSE)
					continue;

				history_type = SERVICE_FLAPPING_HISTORY;

				/* get host and service names */
				temp_buffer = my_strtok(temp_entry->entry_text, ":");
				temp_buffer = my_strtok(NULL, ";");
				if (temp_buffer)
					entry_host_name = strdup(temp_buffer + 1);
				else
					entry_host_name = NULL;
				temp_buffer = my_strtok(NULL, ";");
				if (temp_buffer)
					entry_service_desc = strdup(temp_buffer);
				else
					entry_service_desc = NULL;

				strcpy(image, FLAPPING_ICON);

				if (temp_entry->type == LOGENTRY_SERVICE_FLAPPING_STARTED)
					strcpy(image_alt, "服务开始抖动");
				else if (temp_entry->type == LOGENTRY_SERVICE_FLAPPING_STOPPED)
					strcpy(image_alt, "服务停止抖动");
				else if (temp_entry->type == LOGENTRY_SERVICE_FLAPPING_DISABLED)
					strcpy(image_alt, "禁用服务抖动检测");

				break;

				/* service downtime alerts */
			case LOGENTRY_SERVICE_DOWNTIME_STARTED:
			case LOGENTRY_SERVICE_DOWNTIME_STOPPED:
			case LOGENTRY_SERVICE_DOWNTIME_CANCELLED:

				if (display_downtime_alerts == FALSE)
					continue;

				history_type = SERVICE_DOWNTIME_HISTORY;

				/* get host and service names */
				temp_buffer = my_strtok(temp_entry->entry_text, ":");
				temp_buffer = my_strtok(NULL, ";");
				if (temp_buffer)
					entry_host_name = strdup(temp_buffer + 1);
				else
					entry_host_name = NULL;
				temp_buffer = my_strtok(NULL, ";");
				if (temp_buffer)
					entry_service_desc = strdup(temp_buffer);
				else
					entry_service_desc = NULL;

				strcpy(image, DOWNTIME_ICON);

				if (temp_entry->type == LOGENTRY_SERVICE_DOWNTIME_STARTED)
					strcpy(image_alt, "输入安排服务宕机时");
				else if (temp_entry->type == LOGENTRY_SERVICE_DOWNTIME_STOPPED)
					strcpy(image_alt, "退出安排服务宕机时段");
				else if (temp_entry->type == LOGENTRY_SERVICE_DOWNTIME_CANCELLED)
					strcpy(image_alt, "已取消安排服务宕机");

				break;

				/* host state alerts */
			case LOGENTRY_HOST_DOWN:
			case LOGENTRY_HOST_UNREACHABLE:
			case LOGENTRY_HOST_RECOVERY:
			case LOGENTRY_HOST_UP:

				history_type = HOST_HISTORY;

				/* get host name */
				temp_buffer = my_strtok(temp_entry->entry_text, ":");
				temp_buffer = my_strtok(NULL, ";");
				if (temp_buffer)
					entry_host_name = strdup(temp_buffer + 1);
				else
					entry_host_name = NULL;

				if (temp_entry->type == LOGENTRY_HOST_DOWN) {
					strcpy(image, HOST_DOWN_ICON);
					strcpy(image_alt, HOST_DOWN_ICON_ALT);
					history_detail_type = HISTORY_HOST_DOWN;
				} else if (temp_entry->type == LOGENTRY_HOST_UNREACHABLE) {
					strcpy(image, HOST_UNREACHABLE_ICON);
					strcpy(image_alt, HOST_UNREACHABLE_ICON_ALT);
					history_detail_type = HISTORY_HOST_UNREACHABLE;
				} else if (temp_entry->type == LOGENTRY_HOST_RECOVERY || temp_entry->type == LOGENTRY_HOST_UP) {
					strcpy(image, HOST_UP_ICON);
					strcpy(image_alt, HOST_UP_ICON_ALT);
					history_detail_type = HISTORY_HOST_RECOVERY;
				}

				break;

				/* host flapping alerts */
			case LOGENTRY_HOST_FLAPPING_STARTED:
			case LOGENTRY_HOST_FLAPPING_STOPPED:
			case LOGENTRY_HOST_FLAPPING_DISABLED:

				if (display_flapping_alerts == FALSE)
					continue;

				history_type = HOST_FLAPPING_HISTORY;

				/* get host name */
				temp_buffer = my_strtok(temp_entry->entry_text, ":");
				temp_buffer = my_strtok(NULL, ";");
				if (temp_buffer)
					entry_host_name = strdup(temp_buffer + 1);
				else
					entry_host_name = NULL;

				strcpy(image, FLAPPING_ICON);

				if (temp_entry->type == LOGENTRY_HOST_FLAPPING_STARTED)
					strcpy(image_alt, "主机开始抖动");
				else if (temp_entry->type == LOGENTRY_HOST_FLAPPING_STOPPED)
					strcpy(image_alt, "主机停止抖动");
				else if (temp_entry->type == LOGENTRY_HOST_FLAPPING_DISABLED)
					strcpy(image_alt, "禁用主机抖动检测");

				break;

				/* host downtime alerts */
			case LOGENTRY_HOST_DOWNTIME_STARTED:
			case LOGENTRY_HOST_DOWNTIME_STOPPED:
			case LOGENTRY_HOST_DOWNTIME_CANCELLED:

				if (display_downtime_alerts == FALSE)
					continue;

				history_type = HOST_DOWNTIME_HISTORY;

				/* get host name */
				temp_buffer = my_strtok(temp_entry->entry_text, ":");
				temp_buffer = my_strtok(NULL, ";");
				if (temp_buffer)
					entry_host_name = strdup(temp_buffer + 1);
				else
					entry_host_name = NULL;

				strcpy(image, DOWNTIME_ICON);

				if (temp_entry->type == LOGENTRY_HOST_DOWNTIME_STARTED)
					strcpy(image_alt, "输入安排主机宕机时段");
				else if (temp_entry->type == LOGENTRY_HOST_DOWNTIME_STOPPED)
					strcpy(image_alt, "退出安排主机宕机时段");
				else if (temp_entry->type == LOGENTRY_HOST_DOWNTIME_CANCELLED)
					strcpy(image_alt, "已取消安排主机宕机");

				break;


				/* program start */
			case LOGENTRY_STARTUP:
				if (display_system_messages == FALSE)
					continue;
				strcpy(image, START_ICON);
				strcpy(image_alt, "开始图标");
				system_message = TRUE;
				break;

				/* program termination */
			case LOGENTRY_SHUTDOWN:
			case LOGENTRY_BAILOUT:
				if (display_system_messages == FALSE)
					continue;
				strcpy(image, STOP_ICON);
				strcpy(image_alt, "停止图标");
				system_message = TRUE;
				break;

				/* program restart */
			case LOGENTRY_RESTART:
				if (display_system_messages == FALSE)
					continue;
				strcpy(image, RESTART_ICON);
				strcpy(image_alt, "重启图标");
				system_message = TRUE;
				break;
			}

			image[sizeof(image) - 1] = '\x0';
			image_alt[sizeof(image_alt) - 1] = '\x0';

			/* get the timestamp */
			time_ptr = localtime(&t);
		   /* strftime(current_message_date,sizeof(current_message_date),"%B %d, %Y %H:00\n",time_ptr); */
            get_time_string(&t,current_message_date,sizeof(current_message_date),LOG_DATE);//
			current_message_date[sizeof(current_message_date)-1] = '\x0';

			get_time_string(&temp_entry->timestamp, date_time, sizeof(date_time), SHORT_DATE_TIME);
			strip(date_time);

			if (strcmp(image, "")) {

				display_line = FALSE;

				if (system_message == TRUE)
					display_line = TRUE;

				else if (display_type == DISPLAY_HOSTS || display_type == DISPLAY_HOSTGROUPS) {

					if (history_type == HOST_HISTORY || history_type == SERVICE_HISTORY) {
						snprintf(match1, sizeof(match1), " 主机警告: %s;", host_name);
						snprintf(match2, sizeof(match2), " 服务警告: %s;", host_name);
					} else if (history_type == HOST_FLAPPING_HISTORY || history_type == SERVICE_FLAPPING_HISTORY) {
						snprintf(match1, sizeof(match1), " 主机抖动警告: %s;", host_name);
						snprintf(match2, sizeof(match2), " 服务抖动警告: %s;", host_name);
					} else if (history_type == HOST_DOWNTIME_HISTORY || history_type == SERVICE_DOWNTIME_HISTORY) {
						snprintf(match1, sizeof(match1), " 主机宕机警告: %s;", host_name);
						snprintf(match2, sizeof(match2), " 服务宕机警告: %s;", host_name);
					}

					if (show_all_hosts == TRUE)
						display_line = TRUE;
					else if (strstr(temp_entry->entry_text, match1))
						display_line = TRUE;
					else if (strstr(temp_entry->entry_text, match2))
						display_line = TRUE;

					if (display_line == TRUE) {
						if (history_options == HISTORY_ALL)
							display_line = TRUE;
						else if (history_options == HISTORY_HOST_ALL && (history_type == HOST_HISTORY || history_type == HOST_FLAPPING_HISTORY || history_type == HOST_DOWNTIME_HISTORY))
							display_line = TRUE;
						else if (history_options == HISTORY_SERVICE_ALL && (history_type == SERVICE_HISTORY || history_type == SERVICE_FLAPPING_HISTORY || history_type == SERVICE_DOWNTIME_HISTORY))
							display_line = TRUE;
						else if ((history_type == HOST_HISTORY || history_type == SERVICE_HISTORY) && (history_detail_type & history_options))
							display_line = TRUE;
						else
							display_line = FALSE;
					}

					/* check alert state types */
					if (display_line == TRUE && (history_type == HOST_HISTORY || history_type == SERVICE_HISTORY)) {
						if (state_options == STATE_ALL)
							display_line = TRUE;
						else if ((state_options & STATE_SOFT) && strstr(temp_entry->entry_text, ";软件状态;"))
							display_line = TRUE;
						else if ((state_options & STATE_HARD) && strstr(temp_entry->entry_text, ";硬件状态;"))
							display_line = TRUE;
						else
							display_line = FALSE;
					}
				}

				else if (display_type == DISPLAY_SERVICES || display_type == DISPLAY_SERVICEGROUPS) {

					if (history_type == SERVICE_HISTORY)
						snprintf(match1, sizeof(match1), " 服务警告: %s;%s;", host_name, service_desc);
					else if (history_type == SERVICE_FLAPPING_HISTORY)
						snprintf(match1, sizeof(match1), " 服务抖动警告: %s;%s;", host_name, service_desc);
					else if (history_type == SERVICE_DOWNTIME_HISTORY)
						snprintf(match1, sizeof(match1), " 服务宕机警告: %s;%s;", host_name, service_desc);

					if (display_type == DISPLAY_SERVICEGROUPS)
						display_line = TRUE;
					else if (strstr(temp_entry->entry_text, match1))
						display_line = TRUE;

					if (history_type != SERVICE_HISTORY && history_type != SERVICE_FLAPPING_HISTORY && history_type != SERVICE_DOWNTIME_HISTORY)
						display_line = FALSE;

					if (display_line == TRUE) {
						if (history_options == HISTORY_ALL || history_options == HISTORY_SERVICE_ALL)
							display_line = TRUE;
						else if (history_options & history_detail_type)
							display_line = TRUE;
						else
							display_line = FALSE;
					}

					/* check alert state type */
					if (display_line == TRUE && history_type == SERVICE_HISTORY) {

						if (state_options == STATE_ALL)
							display_line = TRUE;
						else if ((state_options & STATE_SOFT) && strstr(temp_entry->entry_text, ";软件状态;"))
							display_line = TRUE;
						else if ((state_options & STATE_HARD) && strstr(temp_entry->entry_text, ";硬件状态;"))
							display_line = TRUE;
						else
							display_line = FALSE;
					}
				}

				/* make sure user is authorized to view this log entry */
				if (display_line == TRUE) {

					if (system_message == TRUE) {
						if (is_authorized_for_system_information(&current_authdata) == FALSE)
							display_line = FALSE;
					} else {
						temp_host = find_host(entry_host_name);

						if (history_type == HOST_HISTORY || history_type == HOST_FLAPPING_HISTORY || history_type == HOST_DOWNTIME_HISTORY) {
							if (is_authorized_for_host(temp_host, &current_authdata) == FALSE)
								display_line = FALSE;
							else if (display_type == DISPLAY_HOSTGROUPS && is_host_member_of_hostgroup(temp_hostgroup, temp_host) == FALSE)
								display_line = FALSE;
						} else {
							temp_service = find_service(entry_host_name, entry_service_desc);
							if (is_authorized_for_service(temp_service, &current_authdata) == FALSE)
								display_line = FALSE;
							else if (display_type == DISPLAY_HOSTGROUPS && is_host_member_of_hostgroup(temp_hostgroup, temp_host) == FALSE)
								display_line = FALSE;
							else if (display_type == DISPLAY_SERVICEGROUPS && is_service_member_of_servicegroup(temp_servicegroup, temp_service) == FALSE)
								display_line = FALSE;
						}
					}
				}

				/* display the entry if we should... */
				if (display_line == TRUE) {

					if (result_limit != 0  && (((total_entries + 1) < result_start) || (total_entries >= ((result_start + result_limit) - 1)))) {
						total_entries++;
						continue;
					}

					displayed_entries++;
					total_entries++;

					if (strcmp(last_message_date, current_message_date) != 0 && display_timebreaks == TRUE) {
						printf("</DIV><BR CLEAR='all' />\n");
						printf("<DIV CLASS='dateTimeBreak'>\n");
						printf("<table border=0 width=95%%><tr>");
						printf("<td width=40%%><hr width=100%%></td>");
						printf("<td align=center CLASS='dateTimeBreak'>%s</td>", current_message_date);
						printf("<td width=40%%><hr width=100%%></td>");
						printf("</tr></table>\n");
						printf("</DIV>\n");
						printf("<BR CLEAR='all' /><DIV CLASS='logEntries'>\n");
						strncpy(last_message_date, current_message_date, sizeof(last_message_date));
						last_message_date[sizeof(last_message_date) - 1] = '\x0';
					}

					if (display_frills == TRUE)
						printf("<img align='left' src='%s%s' alt='%s' title='%s' />", url_images_path, image, image_alt, image_alt);
					printf("[%s] %s", date_time, html_encode(temp_entry->entry_text, FALSE));
					if (enable_splunk_integration == TRUE) {
						printf("&nbsp;&nbsp;&nbsp;");
						display_splunk_generic_url(temp_entry->entry_text, 2);
					}
					printf("<br clear='all' />\n");
				}
			}

			/* free memory */
			free(entry_host_name);
			entry_host_name = NULL;
			free(entry_service_desc);
			entry_service_desc = NULL;
		}
	}

	free_log_entries(&entry_list);

	printf("</DIV>\n");

	if (total_entries == 0) {
		printf("<HR>\n");
		printf("<DIV CLASS='errorMessage' style='text-align:center'>在日志文件中选定的日期没有发现 ");
		if (display_type == DISPLAY_HOSTS)
			printf("%s", (show_all_hosts == TRUE) ? "" : "该主机的");
		else
			printf("该服务的");
		printf("历史信息.</DIV>");
		printf("<script type='text/javascript'>document.getElementById('hist_page_selector').style.display='none';</script>");
	} else {
		printf("<HR>\n");
		page_num_selector(result_start, total_entries, displayed_entries);
	}

	return;
}
