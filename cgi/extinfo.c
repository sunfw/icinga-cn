/*****************************************************************************
 *
 * EXTINFO.C -  Icinga Extended Information CGI
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

#include "../include/config.h"
#include "../include/common.h"
#include "../include/objects.h"
#include "../include/macros.h"
#include "../include/comments.h"
#include "../include/downtime.h"
#include "../include/statusdata.h"

static icinga_macros *mac;

/* make sure gcc3 won't hit here */
#ifndef GCCTOOOLD
#include "../include/statsprofiler.h"
#endif

#include "../include/cgiutils.h"
#include "../include/getcgi.h"
#include "../include/cgiauth.h"

extern char             nagios_check_command[MAX_INPUT_BUFFER];
extern char             nagios_process_info[MAX_INPUT_BUFFER];

extern time_t		program_start;
extern int              nagios_pid;
extern int              daemon_mode;
extern time_t           last_command_check;
extern time_t           last_log_rotation;
extern int              enable_notifications;
extern time_t		disable_notifications_expire_time;
extern int              execute_service_checks;
extern int              accept_passive_service_checks;
extern int              execute_host_checks;
extern int              accept_passive_host_checks;
extern int              enable_event_handlers;
extern int              obsess_over_services;
extern int              obsess_over_hosts;
extern int              enable_flap_detection;
extern int              enable_failure_prediction;
extern int              process_performance_data;
/* make sure gcc3 won't hit here */
#ifndef GCCTOOOLD
extern int		event_profiling_enabled;
#endif
extern int              buffer_stats[1][3];
extern int              program_stats[MAX_CHECK_STATS_TYPES][3];

extern int              suppress_maintenance_downtime;
extern int		extinfo_show_child_hosts;
extern int		tab_friendly_titles;
extern int		result_limit;

extern char main_config_file[MAX_FILENAME_LENGTH];
extern char url_images_path[MAX_FILENAME_LENGTH];
extern char url_logo_images_path[MAX_FILENAME_LENGTH];

extern int              enable_splunk_integration;

extern char             *notes_url_target;
extern char             *action_url_target;

extern host *host_list;
extern service *service_list;
extern hoststatus *hoststatus_list;
extern servicestatus *servicestatus_list;

extern comment           *comment_list;
extern scheduled_downtime  *scheduled_downtime_list;
extern hoststatus *hoststatus_list;
extern servicestatus *servicestatus_list;
extern hostgroup *hostgroup_list;
extern servicegroup *servicegroup_list;
extern servicedependency *servicedependency_list;
extern hostdependency *hostdependency_list;

/* make sure gcc3 won't hit here */
#ifndef GCCTOOOLD
extern profile_object* profiled_data;
#endif

#define MAX_MESSAGE_BUFFER		4096

#define HEALTH_WARNING_PERCENTAGE       85
#define HEALTH_CRITICAL_PERCENTAGE      75

/* this is only necessary to distinguish between comments and downtime in single host/service view */
#define CSV_DEFAULT			0
#define CSV_COMMENT			1
#define CSV_DOWNTIME			2


/* SORTDATA structure */
typedef struct sortdata_struct {
	int is_service;
	servicestatus *svcstatus;
	hoststatus *hststatus;
	struct sortdata_struct *next;
} sortdata;

int process_cgivars(void);

void show_process_info(void);
void show_host_info(void);
void show_service_info(void);
void show_performance_data(void);
void show_hostgroup_info(void);
void show_servicegroup_info(void);
void show_downtime(int);
void show_scheduling_queue(void);
void show_comments(int);

int sort_data(int, int);
int compare_sortdata_entries(int, int, sortdata *, sortdata *);
void free_sortdata_list(void);

int is_host_child_of_host(host *, host *);

authdata current_authdata;

sortdata *sortdata_list = NULL;

char *host_name = "";
char *hostgroup_name = "";
char *servicegroup_name = "";
char *service_desc = "";

int display_type = DISPLAY_PROCESS_INFO;
int sort_type = SORT_ASCENDING;
int sort_option = SORT_NEXTCHECKTIME;
int csv_type = CSV_DEFAULT;
int get_result_limit = -1;
int result_start = 1;
int total_entries = 0;
int displayed_entries = 0;


int dummy;	/* reduce compiler warnings */

extern int embedded;
extern int refresh;
extern int display_header;
extern int daemon_check;
extern int content_type;

extern char *csv_delimiter;
extern char *csv_data_enclosure;

int CGI_ID = EXTINFO_CGI_ID;

int main(void) {
	int result = OK;
	int found = FALSE;
	char temp_buffer[MAX_INPUT_BUFFER] = "";
	char *processed_string = NULL;
	char *cgi_title = NULL;
	host *temp_host = NULL;
	hostsmember *temp_parenthost = NULL;
	hostgroup *temp_hostgroup = NULL;
	service *temp_service = NULL;
	servicegroup *temp_servicegroup = NULL;
	servicedependency *temp_sd = NULL;
	char *last_hd_hostname = "";
	char *last_sd_svc_desc = "";
	char *last_sd_hostname = "";
	hostdependency *temp_hd = NULL;
	host * child_host;

	mac = get_global_macros();

	/* get the arguments passed in the URL */
	process_cgivars();

	/* reset internal variables */
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

	/* read all status data */
	result = read_all_status_data(main_config_file, READ_ALL_STATUS_DATA);
	if (result == ERROR && daemon_check == TRUE) {
		document_header(CGI_ID, FALSE, "错误");
		print_error(NULL, ERROR_CGI_STATUS_DATA, FALSE);
		document_footer(CGI_ID);
		free_memory();
		return ERROR;
	}

	/* overwrite config value with amount we got via GET */
	result_limit = (get_result_limit != -1) ? get_result_limit : result_limit;

	/* for json and csv output return all by default */
	if (get_result_limit == -1 && (content_type == JSON_CONTENT || content_type == CSV_CONTENT))
		result_limit = 0;

	/* initialize macros */
	init_macros();

	if (tab_friendly_titles == TRUE) {
		if (display_type == DISPLAY_HOST_INFO && host_name && (*host_name != '\0'))
			dummy = asprintf(&cgi_title, "[%s]", html_encode(host_name, FALSE));
		else if (display_type == DISPLAY_SERVICE_INFO && service_desc && *service_desc != '\0' && host_name && *host_name != '\0')
			dummy = asprintf(&cgi_title, "%s @ %s", html_encode(service_desc, FALSE), html_encode(host_name, FALSE));
		else if (display_type == DISPLAY_HOSTGROUP_INFO && hostgroup_name && *hostgroup_name != '\0')
			dummy = asprintf(&cgi_title, "{%s}", html_encode(hostgroup_name, FALSE));
		else if (display_type == DISPLAY_SERVICEGROUP_INFO && servicegroup_name && *servicegroup_name != '\0')
			dummy = asprintf(&cgi_title, "(%s)", html_encode(servicegroup_name, FALSE));
	}

	document_header(CGI_ID, TRUE, (tab_friendly_titles == TRUE && cgi_title != NULL) ? cgi_title : "扩展信息");

	my_free(cgi_title);

	/* get authentication information */
	get_authentication_information(&current_authdata);


	if (display_header == TRUE) {

		/* begin top table */
		printf("<table border=0 width=100%%>\n");
		printf("<tr>\n");

		/* left column of the first row */
		printf("<td align=left valign=top width=33%%>\n");

		if (display_type == DISPLAY_HOST_INFO)
			snprintf(temp_buffer, sizeof(temp_buffer) - 1, "主机信息");
		else if (display_type == DISPLAY_SERVICE_INFO)
			snprintf(temp_buffer, sizeof(temp_buffer) - 1, "服务信息");
		else if (display_type == DISPLAY_COMMENTS)
			snprintf(temp_buffer, sizeof(temp_buffer) - 1, "所有主机和服务的注释");
		else if (display_type == DISPLAY_PERFORMANCE)
			snprintf(temp_buffer, sizeof(temp_buffer) - 1, "性能信息");
		else if (display_type == DISPLAY_HOSTGROUP_INFO)
			snprintf(temp_buffer, sizeof(temp_buffer) - 1, "主机组信息");
		else if (display_type == DISPLAY_SERVICEGROUP_INFO)
			snprintf(temp_buffer, sizeof(temp_buffer) - 1, "服务组信息");
		else if (display_type == DISPLAY_DOWNTIME)
			snprintf(temp_buffer, sizeof(temp_buffer) - 1, "安排所有主机和服务的宕机");
		else if (display_type == DISPLAY_SCHEDULING_QUEUE)
			snprintf(temp_buffer, sizeof(temp_buffer) - 1, "检查调度队列");
		else
			snprintf(temp_buffer, sizeof(temp_buffer) - 1, "Icinga 进程信息");

		temp_buffer[sizeof(temp_buffer) - 1] = '\x0';

		display_info_table(temp_buffer, &current_authdata, daemon_check);

		/* find the host */
		if (display_type == DISPLAY_HOST_INFO || display_type == DISPLAY_SERVICE_INFO) {

			temp_host = find_host(host_name);
			grab_host_macros_r(mac, temp_host);

			if (display_type == DISPLAY_SERVICE_INFO) {
				temp_service = find_service(host_name, service_desc);
				grab_service_macros_r(mac, temp_service);
			}
		}

		/* find the hostgroup */
		else if (display_type == DISPLAY_HOSTGROUP_INFO) {
			temp_hostgroup = find_hostgroup(hostgroup_name);
			grab_hostgroup_macros_r(mac, temp_hostgroup);
		}

		/* find the servicegroup */
		else if (display_type == DISPLAY_SERVICEGROUP_INFO) {
			temp_servicegroup = find_servicegroup(servicegroup_name);
			grab_servicegroup_macros_r(mac, temp_servicegroup);
		}

		if ((display_type == DISPLAY_HOST_INFO && temp_host != NULL) || (display_type == DISPLAY_SERVICE_INFO && temp_host != NULL && temp_service != NULL) || (display_type == DISPLAY_HOSTGROUP_INFO && temp_hostgroup != NULL) || (display_type == DISPLAY_SERVICEGROUP_INFO && temp_servicegroup != NULL)) {

			printf("<TABLE BORDER=1 CELLPADDING=0 CELLSPACING=0 CLASS='linkBox'>\n");
			printf("<TR><TD CLASS='linkBox'>\n");
			if (display_type == DISPLAY_SERVICE_INFO)
				printf("<a href='%s?type=%d&host=%s'>查看该主机信息</a><br>\n", EXTINFO_CGI, DISPLAY_HOST_INFO, url_encode(host_name));
			if (display_type == DISPLAY_SERVICE_INFO || display_type == DISPLAY_HOST_INFO)
				printf("<a href='%s?host=%s'>查看该主机状态详情</a><br>\n", STATUS_CGI, url_encode(host_name));
			if (display_type == DISPLAY_HOST_INFO) {
				printf("<a href='%s?host=%s'>查看该主机警告历史</a><br>\n", HISTORY_CGI, url_encode(host_name));
#ifdef USE_TRENDS
				printf("<a href='%s?host=%s'>查看该主机趋势柱状图</a><br>\n", TRENDS_CGI, url_encode(host_name));
#endif
#ifdef USE_HISTOGRAM
				printf("<a href='%s?host=%s'>查看该主机警告柱状图</a><br>\n", HISTOGRAM_CGI, url_encode(host_name));
#endif
				printf("<a href='%s?host=%s&show_log_entries'>查看该主机可用性报告</b></a><br>\n", AVAIL_CGI, url_encode(host_name));
				printf("<a href='%s?host=%s'>查看该主机通知</a><br>\n", NOTIFICATIONS_CGI, url_encode(host_name));
				printf("<a href='%s?type=%d&host=%s'>查看该主机排程队列</a><br>\n", EXTINFO_CGI, DISPLAY_SCHEDULING_QUEUE, url_encode(host_name));
				if (is_authorized_for_configuration_information(&current_authdata) == TRUE)
					printf("<a href='%s?type=hosts&item_name=%s'>查看该主机配置</a>\n", CONFIG_CGI, url_encode(host_name));
			} else if (display_type == DISPLAY_SERVICE_INFO) {
				printf("<a href='%s?host=%s&service=%s'>查看该服务警告历史</a><br>\n", HISTORY_CGI, url_encode(host_name), url_encode(service_desc));
#ifdef USE_TRENDS
				printf("<a href='%s?host=%s&service=%s'>查看该服务趋势</a><br>\n", TRENDS_CGI, url_encode(host_name), url_encode(service_desc));
#endif
#ifdef USE_HISTOGRAM
				printf("<a href='%s?host=%s&service=%s'>查看该服务警告柱状图</a><br>\n", HISTOGRAM_CGI, url_encode(host_name), url_encode(service_desc));
#endif
				printf("<a href='%s?host=%s&service=%s&show_log_entries'>查看该服务可用性报告</a><br>\n", AVAIL_CGI, url_encode(host_name), url_encode(service_desc));
				printf("<a href='%s?host=%s&service=%s'>查看该服务通知</a><br>\n", NOTIFICATIONS_CGI, url_encode(host_name), url_encode(service_desc));
				printf("<a href='%s?type=%d&host=%s&service=%s'>查看该服务排程队列</a><br>\n", EXTINFO_CGI, DISPLAY_SCHEDULING_QUEUE, url_encode(host_name), url_encode(service_desc));
				if (is_authorized_for_configuration_information(&current_authdata) == TRUE)
					printf("<a href='%s?type=services&item_name=%s^%s'>查看该服务配置</a>\n", CONFIG_CGI, url_encode(host_name), url_encode(service_desc));
			} else if (display_type == DISPLAY_HOSTGROUP_INFO) {
				printf("<a href='%s?hostgroup=%s&style=detail'>查看该主机组状态详情</a><br>\n", STATUS_CGI, url_encode(hostgroup_name));
				printf("<a href='%s?hostgroup=%s&style=overview'>查看该主机组状态概况</a><br>\n", STATUS_CGI, url_encode(hostgroup_name));
				printf("<a href='%s?hostgroup=%s&style=grid'>查看该主机组状态网格</a><br>\n", STATUS_CGI, url_encode(hostgroup_name));
				printf("<a href='%s?hostgroup=%s'>查看该主机组警告历史</a><br>\n", HISTORY_CGI, url_encode(hostgroup_name));
				printf("<a href='%s?hostgroup=%s'>查看该主机组可用性报告</a><br>\n", AVAIL_CGI, url_encode(hostgroup_name));
				printf("<a href='%s?hostgroup=%s'>查看该主机组通知</a><br>\n", NOTIFICATIONS_CGI, url_encode(hostgroup_name));
				if (is_authorized_for_configuration_information(&current_authdata) == TRUE)
					printf("<a href='%s?type=hostgroups&item_name=%s'>查看该主机组配置</a>\n", CONFIG_CGI, url_encode(hostgroup_name));
			} else if (display_type == DISPLAY_SERVICEGROUP_INFO) {
				printf("<a href='%s?servicegroup=%s&style=detail'>查看该服务组状态详情</a><br>\n", STATUS_CGI, url_encode(servicegroup_name));
				printf("<a href='%s?servicegroup=%s&style=overview'>查看该服务组状态概况</a><br>\n", STATUS_CGI, url_encode(servicegroup_name));
				printf("<a href='%s?servicegroup=%s&style=grid'>查看该服务组状态网格</a><br>\n", STATUS_CGI, url_encode(servicegroup_name));
				printf("<a href='%s?servicegroup=%s'>查看该服务组警告历史</a><br>\n", HISTORY_CGI, url_encode(servicegroup_name));
				printf("<a href='%s?servicegroup=%s'>查看该服务组可用性报告</a><br>\n", AVAIL_CGI, url_encode(servicegroup_name));
				printf("<a href='%s?servicegroup=%s'>查看该服务组警告历史</a><br>\n", NOTIFICATIONS_CGI, url_encode(servicegroup_name));
				if (is_authorized_for_configuration_information(&current_authdata) == TRUE)
					printf("<a href='%s?type=servicegroups&item_name=%s'>查看该服务组配置</a>\n", CONFIG_CGI, url_encode(servicegroup_name));
			}
			printf("</TD></TR>\n");
			printf("</TABLE>\n");
		}

		printf("</td>\n");

		/* middle column of top row */
		printf("<td align=center valign=middle width=33%%>\n");

		if ((display_type == DISPLAY_HOST_INFO && temp_host != NULL) || (display_type == DISPLAY_SERVICE_INFO && temp_host != NULL && temp_service != NULL) || (display_type == DISPLAY_HOSTGROUP_INFO && temp_hostgroup != NULL) || (display_type == DISPLAY_SERVICEGROUP_INFO && temp_servicegroup != NULL)) {

			if (display_type == DISPLAY_HOST_INFO) {

				printf("<DIV CLASS='data'>主机</DIV>\n");
				printf("<DIV CLASS='dataTitle'>%s</DIV>\n", temp_host->alias);
				printf("<DIV CLASS='dataTitle'>(%s)</DIV><BR>\n", (temp_host->display_name != NULL) ? temp_host->display_name : temp_host->name);

				if (temp_host->parent_hosts != NULL) {
					/* print all parent hosts */
					printf("<DIV CLASS='data'>父级:</DIV>\n");
					for (temp_parenthost = temp_host->parent_hosts; temp_parenthost != NULL; temp_parenthost = temp_parenthost->next)
						printf("<DIV CLASS='dataTitle'><A HREF='%s?host=%s'>%s</A></DIV>\n", STATUS_CGI, url_encode(temp_parenthost->host_name), temp_parenthost->host_name);
				}

				/* Hostgroups */
				printf("<DIV CLASS='data'>属于</DIV><DIV CLASS='dataTitle'>");

				for (temp_hostgroup = hostgroup_list; temp_hostgroup != NULL; temp_hostgroup = temp_hostgroup->next) {
					if (is_host_member_of_hostgroup(temp_hostgroup, temp_host) == TRUE) {
						if (found == TRUE)
							printf(", ");

						printf("<A HREF='%s?hostgroup=%s&style=overview'>%s</A>", STATUS_CGI, url_encode(temp_hostgroup->group_name), html_encode((temp_hostgroup->alias != NULL) ? temp_hostgroup->alias : temp_hostgroup->group_name, TRUE));
						found = TRUE;
					}
				}

				if (found == FALSE)
					printf("无主机组");

				printf("</DIV>\n");

				/* Child Hosts */
				if (extinfo_show_child_hosts == SHOW_CHILD_HOSTS_IMMEDIATE || extinfo_show_child_hosts == SHOW_CHILD_HOSTS_ALL) {
					found = FALSE;

					printf("<DIV CLASS='data'>直接子主机 ");
					printf("<img id='expand_image_immediate' src='%s%s' border=0 onClick=\"if (document.getElementById('immediate_child_hosts').style.display == 'none') { document.getElementById('immediate_child_hosts').style.display = ''; document.getElementById('immediate_child_hosts_gap').style.display = 'none'; document.getElementById('expand_image_immediate').src = '%s%s'; } else { document.getElementById('immediate_child_hosts').style.display = 'none'; document.getElementById('immediate_child_hosts_gap').style.display = ''; document.getElementById('expand_image_immediate').src = '%s%s'; }\">", url_images_path, EXPAND_ICON, url_images_path, COLLAPSE_ICON, url_images_path, EXPAND_ICON);
					printf("</DIV><DIV CLASS='dataTitle' id='immediate_child_hosts_gap' style='display:;'>&nbsp;</DIV><DIV CLASS='dataTitle' id='immediate_child_hosts' style='display:none;'>");

					for (child_host = host_list; child_host != NULL; child_host = child_host->next) {
						if (is_host_immediate_child_of_host(temp_host, child_host) == TRUE) {
							if (found == TRUE)
								printf(", ");

							printf("<A HREF='%s?type=%d&host=%s'>%s</A>", EXTINFO_CGI, DISPLAY_HOST_INFO, url_encode(child_host->name), html_encode(child_host->name, TRUE));
							found = TRUE;
						}
					}

					if (found == FALSE)
						printf("无");

					printf("</DIV>\n");

					if (extinfo_show_child_hosts == SHOW_CHILD_HOSTS_ALL) {
						found = FALSE;

						printf("<DIV CLASS='data'>所有子主机 ");
						printf("<img id='expand_image_all' src='%s%s' border=0 onClick=\"if (document.getElementById('all_child_hosts').style.display == 'none') { document.getElementById('all_child_hosts').style.display = ''; document.getElementById('all_child_hosts_gap').style.display = 'none'; document.getElementById('expand_image_all').src = '%s%s'; } else { document.getElementById('all_child_hosts').style.display = 'none'; document.getElementById('all_child_hosts_gap').style.display = ''; document.getElementById('expand_image_all').src = '%s%s'; }\">", url_images_path, EXPAND_ICON, url_images_path, COLLAPSE_ICON, url_images_path, EXPAND_ICON);
						printf("</DIV><DIV CLASS='dataTitle' id='all_child_hosts_gap' style='display:;'>&nbsp;</DIV><DIV CLASS='dataTitle' id='all_child_hosts' style='display:none;'>");

						for (child_host = host_list; child_host != NULL; child_host = child_host->next) {
							if (is_host_child_of_host(temp_host, child_host) == TRUE) {
								if (found == TRUE)
									printf(", ");

								printf("<A HREF='%s?type=%d&host=%s'>%s</A>", EXTINFO_CGI, DISPLAY_HOST_INFO, url_encode(child_host->name), html_encode(child_host->name, TRUE));

								found = TRUE;
							}
						}

						if (found == FALSE)
							printf("无");

						printf("</DIV>\n");
					}
				}

				/* Host Dependencies */
				found = FALSE;

				printf("<DIV CLASS='data'>主机依赖 ");
				printf("<img id='expand_image_hd' src='%s%s' border=0 onClick=\"if (document.getElementById('host_dependencies').style.display == 'none') { document.getElementById('host_dependencies').style.display = ''; document.getElementById('host_dependencies_gap').style.display = 'none'; document.getElementById('expand_image_hd').src = '%s%s'; } else { document.getElementById('host_dependencies').style.display = 'none'; document.getElementById('host_dependencies_gap').style.display = ''; document.getElementById('expand_image_hd').src = '%s%s'; }\">", url_images_path, EXPAND_ICON, url_images_path, COLLAPSE_ICON, url_images_path, EXPAND_ICON);
				printf("</DIV><DIV CLASS='dataTitle' id='host_dependencies_gap' style='display:;'>&nbsp;</DIV><DIV CLASS='dataTitle' id='host_dependencies' style='display:none;'>");

				for (temp_hd = hostdependency_list; temp_hd != NULL; temp_hd = temp_hd->next) {

					if (!strcmp(temp_hd->dependent_host_name, temp_host->name)) {
						if (!strcmp(temp_hd->host_name, last_hd_hostname)) {
							if (found == TRUE)
								printf(", ");

							printf("<A HREF='%s?type=%d&host=%s'>%s</A><BR>\n", EXTINFO_CGI, DISPLAY_HOST_INFO, url_encode(temp_hd->host_name), html_encode(temp_hd->host_name, FALSE));
							found = TRUE;
						}
						last_hd_hostname = temp_hd->host_name;
					}
				}

				if (found == FALSE)
					printf("无");

				printf("</DIV>\n");

				/* Host address(6) */
				if (!strcmp(temp_host->address6, temp_host->name)) {
					printf("<DIV CLASS='data'>%s</DIV>\n", temp_host->address);
				} else {
					printf("<DIV CLASS='data'>%s, %s</DIV>\n", temp_host->address, temp_host->address6);
				}
			}
			if (display_type == DISPLAY_SERVICE_INFO) {

				printf("<DIV CLASS='data'>服务</DIV><DIV CLASS='dataTitle'>%s</DIV><DIV CLASS='data'>位于主机</DIV>\n", (temp_service->display_name != NULL) ? temp_service->display_name : temp_service->description);
				printf("<DIV CLASS='dataTitle'>%s</DIV>\n", temp_host->alias);
				printf("<DIV CLASS='dataTitle'>(<A HREF='%s?type=%d&host=%s'>%s</a>)</DIV><BR>\n", EXTINFO_CGI, DISPLAY_HOST_INFO, url_encode(temp_host->name), (temp_host->display_name != NULL) ? temp_host->display_name : temp_host->name);

				/* Servicegroups */
				printf("<DIV CLASS='data'>属于</DIV><DIV CLASS='dataTitle'>");

				for (temp_servicegroup = servicegroup_list; temp_servicegroup != NULL; temp_servicegroup = temp_servicegroup->next) {
					if (is_service_member_of_servicegroup(temp_servicegroup, temp_service) == TRUE) {
						if (found == TRUE)
							printf(", ");

						printf("<A HREF='%s?servicegroup=%s&style=overview'>%s</A>", STATUS_CGI, url_encode(temp_servicegroup->group_name), html_encode((temp_servicegroup->alias != NULL) ? temp_servicegroup->alias : temp_servicegroup->group_name, TRUE));
						found = TRUE;
					}
				}

				if (found == FALSE)
					printf("无服务组.");

				printf("</DIV>\n");

				/* Service Dependencies */
				found = FALSE;

				printf("<DIV CLASS='data'>服务依赖 ");
				printf("<img id='expand_image_sd' src='%s%s' border=0 onClick=\"if (document.getElementById('service_dependencies').style.display == 'none') { document.getElementById('service_dependencies').style.display = ''; document.getElementById('service_dependencies_gap').style.display = 'none'; document.getElementById('expand_image_sd').src = '%s%s'; } else { document.getElementById('service_dependencies').style.display = 'none'; document.getElementById('service_dependencies_gap').style.display = ''; document.getElementById('expand_image_sd').src = '%s%s'; }\">", url_images_path, EXPAND_ICON, url_images_path, COLLAPSE_ICON, url_images_path, EXPAND_ICON);
				printf("</DIV><DIV CLASS='dataTitle' id='service_dependencies_gap' style='display:;'>&nbsp;</DIV><DIV CLASS='dataTitle' id='service_dependencies' style='display:none;'>");

				for (temp_sd = servicedependency_list; temp_sd != NULL; temp_sd = temp_sd->next) {

					if (!strcmp(temp_sd->dependent_service_description, temp_service->description) && !strcmp(temp_sd->dependent_host_name, temp_host->name)) {
					        if (!(!strcmp(temp_sd->service_description, last_sd_svc_desc) && !strcmp(temp_sd->host_name, last_sd_hostname))) {
							if (found == TRUE)
								printf(", ");

							printf("<A HREF='%s?type=%d&host=%s", EXTINFO_CGI, DISPLAY_SERVICE_INFO, url_encode(temp_sd->host_name));
							printf("&service=%s'>%s 位于 %s</A>\n", url_encode(temp_sd->service_description), html_encode(temp_sd->service_description, FALSE), html_encode(temp_sd->host_name, FALSE));
							found = TRUE;
						}
						last_sd_svc_desc = temp_sd->service_description;
						last_sd_hostname = temp_sd->host_name;
					}
				}

				if (found == FALSE)
					printf("无");

				printf("</DIV>\n");


				if (!strcmp(temp_host->address6, temp_host->name)) {
					printf("<DIV CLASS='data'>%s</DIV>\n", temp_host->address);
				} else {
					printf("<DIV CLASS='data'>%s, %s</DIV>\n", temp_host->address, temp_host->address6);
				}
			}
			if (display_type == DISPLAY_HOSTGROUP_INFO) {

				printf("<DIV CLASS='data'>主机组</DIV>\n");
				printf("<DIV CLASS='dataTitle'>%s</DIV>\n", temp_hostgroup->alias);
				printf("<DIV CLASS='dataTitle'>(%s)</DIV>\n", temp_hostgroup->group_name);

				if (temp_hostgroup->notes != NULL) {
					process_macros_r(mac, temp_hostgroup->notes, &processed_string, 0);
					printf("<p>%s</p>", processed_string);
					free(processed_string);
				}
			}
			if (display_type == DISPLAY_SERVICEGROUP_INFO) {

				printf("<DIV CLASS='data'>服务组</DIV>\n");
				printf("<DIV CLASS='dataTitle'>%s</DIV>\n", temp_servicegroup->alias);
				printf("<DIV CLASS='dataTitle'>(%s)</DIV>\n", temp_servicegroup->group_name);

				if (temp_servicegroup->notes != NULL) {
					process_macros_r(mac, temp_servicegroup->notes, &processed_string, 0);
					printf("<p>%s</p>", processed_string);
					free(processed_string);
				}
			}

			if (display_type == DISPLAY_SERVICE_INFO) {
				if (temp_service->icon_image != NULL) {
					printf("<img src='%s", url_logo_images_path);
					process_macros_r(mac, temp_service->icon_image, &processed_string, 0);
					printf("%s", processed_string);
					free(processed_string);
					printf("' border=0 alt='%s' title='%s'><BR CLEAR=ALL>", (temp_service->icon_image_alt == NULL) ? "" : temp_service->icon_image_alt, (temp_service->icon_image_alt == NULL) ? "" : temp_service->icon_image_alt);
				}
				if (temp_service->icon_image_alt != NULL)
					printf("<font size=-1><i>( %s )</i></font>\n", temp_service->icon_image_alt);
				if (temp_service->notes != NULL) {
					process_macros_r(mac, temp_service->notes, &processed_string, 0);
					printf("<p>%s</p>\n", processed_string);
					free(processed_string);
				}
			}

			if (display_type == DISPLAY_HOST_INFO) {
				if (temp_host->icon_image != NULL) {
					printf("<img src='%s", url_logo_images_path);
					process_macros_r(mac, temp_host->icon_image, &processed_string, 0);
					printf("%s", processed_string);
					free(processed_string);
					printf("' border=0 alt='%s' title='%s'><BR CLEAR=ALL>", (temp_host->icon_image_alt == NULL) ? "" : temp_host->icon_image_alt, (temp_host->icon_image_alt == NULL) ? "" : temp_host->icon_image_alt);
				}
				if (temp_host->icon_image_alt != NULL)
					printf("<font size=-1><i>( %s )</i><font>\n", temp_host->icon_image_alt);
				if (temp_host->notes != NULL) {
					process_macros_r(mac, temp_host->notes, &processed_string, 0);
					printf("<p>%s</p>\n", processed_string);
					free(processed_string);
				}
			}
		}

		printf("</td>\n");

		/* right column of top row */
		printf("<td align=right valign=bottom width=33%%>\n");

		if (display_type == DISPLAY_HOST_INFO && temp_host != NULL) {

			printf("<TABLE BORDER='0'>\n");
			if (temp_host->action_url != NULL && strcmp(temp_host->action_url, "")) {
				process_macros_r(mac, temp_host->action_url, &processed_string, 0);
				BEGIN_MULTIURL_LOOP
				printf("<TR><TD ALIGN='right'>\n");
				printf("<A HREF='");
				printf("%s", processed_string);
				printf("' TARGET='%s'><img src='%s%s%s' border=0 alt='在该主机上执行额外的动作' title='在该主机上执行额外的动作'></A>\n", (action_url_target == NULL) ? "_blank" : action_url_target, url_images_path, MU_iconstr, ACTION_ICON);
				printf("<BR CLEAR=ALL><FONT SIZE=-1><I>额外动作</I></FONT><BR CLEAR=ALL><BR CLEAR=ALL>\n");
				printf("</TD></TR>\n");
				END_MULTIURL_LOOP
				free(processed_string);
			}
			if (temp_host->notes_url != NULL && strcmp(temp_host->notes_url, "")) {
				process_macros_r(mac, temp_host->notes_url, &processed_string, 0);
				BEGIN_MULTIURL_LOOP
				printf("<TR><TD ALIGN='right'>\n");
				printf("<A HREF='");
				printf("%s", processed_string);
				/*print_extra_host_url(temp_host->name,temp_host->notes_url);*/
				printf("' TARGET='%s'><img src='%s%s%s' border=0 alt='查看该主机额外的备注' title='查看该主机额外的备注'></A>\n", (notes_url_target == NULL) ? "_blank" : notes_url_target, url_images_path, MU_iconstr, NOTES_ICON);
				printf("<BR CLEAR=ALL><FONT SIZE=-1><I>额外备注</I></FONT><BR CLEAR=ALL><BR CLEAR=ALL>\n");
				printf("</TD></TR>\n");
				END_MULTIURL_LOOP
				free(processed_string);
			}
			printf("</TABLE>\n");
		}

		else if (display_type == DISPLAY_SERVICE_INFO && temp_service != NULL) {

			printf("<TABLE BORDER='0'><TR><TD ALIGN='right'>\n");

			if (temp_service->action_url != NULL && strcmp(temp_service->action_url, "")) {
				process_macros_r(mac, temp_service->action_url, &processed_string, 0);
				BEGIN_MULTIURL_LOOP
				printf("<A HREF='");
				printf("%s", processed_string);
				printf("' TARGET='%s'><img src='%s%s%s' border=0 alt='在该服务上执行额外的动作' title='在该服务上执行额外的动作'></A>\n", (action_url_target == NULL) ? "_blank" : action_url_target, url_images_path, MU_iconstr, ACTION_ICON);
				printf("<BR CLEAR=ALL><FONT SIZE=-1><I>额外动作</I></FONT><BR CLEAR=ALL><BR CLEAR=ALL>\n");
				END_MULTIURL_LOOP
				free(processed_string);
			}
			if (temp_service->notes_url != NULL && strcmp(temp_service->notes_url, "")) {
				process_macros_r(mac, temp_service->notes_url, &processed_string, 0);
				BEGIN_MULTIURL_LOOP
				printf("<A HREF='");
				printf("%s", processed_string);
				printf("' TARGET='%s'><img src='%s%s%s' border=0 alt='查看该服务额外的备注' title='查看该服务额外的备注'></A>\n", (notes_url_target == NULL) ? "_blank" : notes_url_target, url_images_path, MU_iconstr, NOTES_ICON);
				printf("<BR CLEAR=ALL><FONT SIZE=-1><I>额外备注</I></FONT><BR CLEAR=ALL><BR CLEAR=ALL>\n");
				END_MULTIURL_LOOP
				free(processed_string);
			}
			printf("</TD></TR></TABLE>\n");
		}

		if (display_type == DISPLAY_HOSTGROUP_INFO && temp_hostgroup != NULL) {
			printf("<TABLE BORDER='0'>\n");

			if (temp_hostgroup->action_url != NULL && strcmp(temp_hostgroup->action_url, "")) {
				printf("<TR><TD ALIGN='right'>\n");
				printf("<A HREF='");
				print_extra_hostgroup_url(temp_hostgroup->group_name, temp_hostgroup->action_url);
				printf("' TARGET='%s'><img src='%s%s' border=0 alt='在该主机组执行额外动作' title='在该主机组执行额外动作'></A>\n", (action_url_target == NULL) ? "_blank" : action_url_target, url_images_path, ACTION_ICON);
				printf("<BR CLEAR=ALL><FONT SIZE=-1><I>额外动作</I></FONT><BR CLEAR=ALL><BR CLEAR=ALL>\n");
				printf("</TD></TR>\n");
			}
			if (temp_hostgroup->notes_url != NULL && strcmp(temp_hostgroup->notes_url, "")) {
				printf("<TR><TD ALIGN='right'>\n");
				printf("<A HREF='");
				print_extra_hostgroup_url(temp_hostgroup->group_name, temp_hostgroup->notes_url);
				printf("' TARGET='%s'><img src='%s%s' border=0 alt='查看该主机组的额外备注' title='查看该主机组的额外备注'></A>\n", (notes_url_target == NULL) ? "_blank" : notes_url_target, url_images_path, NOTES_ICON);
				printf("<BR CLEAR=ALL><FONT SIZE=-1><I>额外备注</I></FONT><BR CLEAR=ALL><BR CLEAR=ALL>\n");
				printf("</TD></TR>\n");
			}
			printf("</TABLE>\n");
		}

		else if (display_type == DISPLAY_SERVICEGROUP_INFO && temp_servicegroup != NULL) {
			printf("<TABLE BORDER='0'>\n");

			if (temp_servicegroup->action_url != NULL && strcmp(temp_servicegroup->action_url, "")) {
				printf("<A HREF='");
				print_extra_servicegroup_url(temp_servicegroup->group_name, temp_servicegroup->action_url);
				printf("' TARGET='%s'><img src='%s%s' border=0 alt='在该服务组执行额外动作' title='在该服务组执行额外动作'></A>\n", (action_url_target == NULL) ? "_blank" : action_url_target, url_images_path, ACTION_ICON);
				printf("<BR CLEAR=ALL><FONT SIZE=-1><I>额外动作</I></FONT><BR CLEAR=ALL><BR CLEAR=ALL>\n");
			}
			if (temp_servicegroup->notes_url != NULL && strcmp(temp_servicegroup->notes_url, "")) {
				printf("<A HREF='");
				print_extra_servicegroup_url(temp_servicegroup->group_name, temp_servicegroup->notes_url);
				printf("' TARGET='%s'><img src='%s%s' border=0 alt=查看服务组额外的备注' title='查看服务组额外的备注'></A>\n", (notes_url_target == NULL) ? "_blank" : notes_url_target, url_images_path, NOTES_ICON);
				printf("<BR CLEAR=ALL><FONT SIZE=-1><I>额外备注</I></FONT><BR CLEAR=ALL><BR CLEAR=ALL>\n");
			}
			printf("</TABLE>\n");
		}

		printf("</td>\n");

		/* end of top table */
		printf("</tr>\n");
		printf("</table>\n");

	}

	if (content_type == HTML_CONTENT) {
		if (display_type == DISPLAY_HOST_INFO || display_type == DISPLAY_SERVICE_INFO) {
			printf("<DIV style='padding-right:6px;' class='csv_export_link'>");
			print_export_link(JSON_CONTENT, EXTINFO_CGI, NULL);
			print_export_link(HTML_CONTENT, EXTINFO_CGI, NULL);
			printf("</DIV>");
		} else
			printf("<BR>\n");
	}

	if (display_type == DISPLAY_HOST_INFO) {
		if (content_type == CSV_CONTENT) {
			if (csv_type == CSV_COMMENT)
				show_comments(HOST_COMMENT);
			else if (csv_type == CSV_DOWNTIME)
				show_downtime(HOST_DOWNTIME);
			else
				printf("请指定正确的csv类型! 可能是 \"csvtype=注释\" 或 \"csv_type=宕机\".\n");
		} else
			show_host_info();
	} else if (display_type == DISPLAY_SERVICE_INFO) {
		if (content_type == CSV_CONTENT) {
			if (csv_type == CSV_COMMENT)
				show_comments(SERVICE_COMMENT);
			else if (csv_type == CSV_DOWNTIME)
				show_downtime(SERVICE_DOWNTIME);
			else
				printf("请指定正确的csv类型! 可能是 \"csvtype=注释\" 或 \"csv_type=宕机\".\n");
		} else
			show_service_info();
	} else if (display_type == DISPLAY_COMMENTS) {
		if (is_authorized_for_read_only(&current_authdata) == TRUE && is_authorized_for_comments_read_only(&current_authdata) == FALSE)
			printf("<DIV ALIGN=CENTER CLASS='infoMessage'>您的帐户没有权限查看注释.<br>\n");
		else {
			if (content_type == CSV_CONTENT || content_type == JSON_CONTENT) {
				show_comments(HOST_COMMENT);
				if (content_type == JSON_CONTENT)
					printf(",\n");
				show_comments(SERVICE_COMMENT);
			} else {
				printf("<BR>\n");
				printf("<DIV CLASS='commentNav'>[&nbsp;<A HREF='#HOSTCOMMENTS' CLASS='commentNav'>主机注释</A>&nbsp;|&nbsp;<A HREF='#SERVICECOMMENTS' CLASS='commentNav'>服务注释</A>&nbsp;]</DIV>\n");
				printf("<BR>\n");

				show_comments(HOST_COMMENT);
				printf("<br>\n");
				show_comments(SERVICE_COMMENT);
			}
		}
	} else if (display_type == DISPLAY_DOWNTIME) {
		if (is_authorized_for_read_only(&current_authdata) == TRUE && is_authorized_for_downtimes_read_only(&current_authdata) == FALSE)
			printf("<DIV ALIGN=CENTER CLASS='infoMessage'>您的帐户没有权限查看宕机.<br>\n");
		else {
			if (content_type == CSV_CONTENT || content_type == JSON_CONTENT) {
				show_downtime(HOST_DOWNTIME);
				if (content_type == JSON_CONTENT)
					printf(",\n");
				show_downtime(SERVICE_DOWNTIME);
			} else {
				printf("<br>\n");
				printf("<DIV CLASS='downtimeNav'>[&nbsp;<A HREF='#HOSTDOWNTIME' CLASS='downtimeNav'>主机宕机</A>&nbsp;|&nbsp;<A HREF='#SERVICEDOWNTIME' CLASS='downtimeNav'>服务宕机</A>&nbsp;]</DIV>\n");
				printf("<br>\n");

				show_downtime(HOST_DOWNTIME);
				printf("<br>\n");
				show_downtime(SERVICE_DOWNTIME);
			}
		}
	} else if (display_type == DISPLAY_PERFORMANCE)
		show_performance_data();
	else if (display_type == DISPLAY_HOSTGROUP_INFO)
		show_hostgroup_info();
	else if (display_type == DISPLAY_SERVICEGROUP_INFO)
		show_servicegroup_info();
	else if (display_type == DISPLAY_SCHEDULING_QUEUE)
		show_scheduling_queue();
	else
		show_process_info();

	document_footer(CGI_ID);

	/* free all allocated memory */
	free_memory();
	free_comment_data();
	free_downtime_data();

	return OK;
}

int process_cgivars(void) {
	char **variables;
	int error = FALSE;
	int temp_type;
	int x;

	variables = getcgivars();

	for (x = 0; variables[x] != NULL; x++) {

		/* do some basic length checking on the variable identifier to prevent buffer overflows */
		if (strlen(variables[x]) >= MAX_INPUT_BUFFER - 1) {
			x++;
			continue;
		}

		/* we found the display type */
		else if (!strcmp(variables[x], "type")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}
			temp_type = atoi(variables[x]);
			if (temp_type == DISPLAY_HOST_INFO)
				display_type = DISPLAY_HOST_INFO;
			else if (temp_type == DISPLAY_SERVICE_INFO)
				display_type = DISPLAY_SERVICE_INFO;
			else if (temp_type == DISPLAY_COMMENTS)
				display_type = DISPLAY_COMMENTS;
			else if (temp_type == DISPLAY_PERFORMANCE)
				display_type = DISPLAY_PERFORMANCE;
			else if (temp_type == DISPLAY_HOSTGROUP_INFO)
				display_type = DISPLAY_HOSTGROUP_INFO;
			else if (temp_type == DISPLAY_SERVICEGROUP_INFO)
				display_type = DISPLAY_SERVICEGROUP_INFO;
			else if (temp_type == DISPLAY_DOWNTIME)
				display_type = DISPLAY_DOWNTIME;
			else if (temp_type == DISPLAY_SCHEDULING_QUEUE)
				display_type = DISPLAY_SCHEDULING_QUEUE;
			else
				display_type = DISPLAY_PROCESS_INFO;
		}

		/* we found the host name */
		else if (!strcmp(variables[x], "host")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			host_name = strdup(variables[x]);
			if (host_name == NULL)
				host_name = "";
			strip_html_brackets(host_name);
		}

		/* we found the hostgroup name */
		else if (!strcmp(variables[x], "hostgroup")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			hostgroup_name = strdup(variables[x]);
			if (hostgroup_name == NULL)
				hostgroup_name = "";
			strip_html_brackets(hostgroup_name);
		}

		/* we found the service name */
		else if (!strcmp(variables[x], "service")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			service_desc = strdup(variables[x]);
			if (service_desc == NULL)
				service_desc = "";
			strip_html_brackets(service_desc);
		}

		/* we found the servicegroup name */
		else if (!strcmp(variables[x], "servicegroup")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			servicegroup_name = strdup(variables[x]);
			if (servicegroup_name == NULL)
				servicegroup_name = "";
			strip_html_brackets(servicegroup_name);
		}

		/* we found the sort type argument */
		else if (!strcmp(variables[x], "sorttype")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			sort_type = atoi(variables[x]);
		}

		/* we found the sort option argument */
		else if (!strcmp(variables[x], "sortoption")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			sort_option = atoi(variables[x]);
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

		else if (!strcmp(variables[x], "csvtype")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (!strcmp(variables[x], "comment"))
				csv_type = CSV_COMMENT;
			else if (!strcmp(variables[x], "downtime"))
				csv_type = CSV_DOWNTIME;
			else
				csv_type = CSV_DEFAULT;
		}

		/* we found the embed option */
		else if (!strcmp(variables[x], "embedded"))
			embedded = TRUE;

		/* we found the noheader option */
		else if (!strcmp(variables[x], "noheader"))
			display_header = FALSE;

		/* we found the pause option */
		else if (!strcmp(variables[x], "paused"))
			refresh = FALSE;

		/* we found the nodaemoncheck option */
		else if (!strcmp(variables[x], "nodaemoncheck"))
			daemon_check = FALSE;

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

void show_process_info(void) {
	char start_time[MAX_DATETIME_LENGTH];
	char last_external_check_time[MAX_DATETIME_LENGTH];
	char last_log_rotation_time[MAX_DATETIME_LENGTH];
	char disable_notif_expire_time[MAX_DATETIME_LENGTH];
	time_t current_time;
	unsigned long run_time;
	char run_time_string[24];
	int days = 0;
	int hours = 0;
	int minutes = 0;
	int seconds = 0;

	/* make sure the user has rights to view system information */
	if (is_authorized_for_system_information(&current_authdata) == FALSE) {

		print_generic_error_message("很显然您没有权限查看进程信息...","如果您认为这是一个错误, 请检查访问CGI的HTTP服务器身份验证要求,并检查您的CGI配置文件的授权选项.", 0);

		return;
	}

	/* program start time */
	get_time_string(&program_start, start_time, (int)sizeof(start_time), SHORT_DATE_TIME);

	/* total running time */
	time(&current_time);
	run_time = (unsigned long)(current_time - program_start);
	get_time_breakdown(run_time, &days, &hours, &minutes, &seconds);
	sprintf(run_time_string, "%2d天%2d时%2d分%2d秒", days, hours, minutes, seconds);

	/* last external check */
	get_time_string(&last_command_check, last_external_check_time, (int)sizeof(last_external_check_time), SHORT_DATE_TIME);

	/* last log file rotation */
	get_time_string(&last_log_rotation, last_log_rotation_time, (int)sizeof(last_log_rotation_time), SHORT_DATE_TIME);

	/* disabled notifications expire time */
	get_time_string(&disable_notifications_expire_time, disable_notif_expire_time, (int)sizeof(disable_notif_expire_time), SHORT_DATE_TIME);

	if (content_type == JSON_CONTENT) {
		printf("\"进程信息\": {\n");
		printf("\"程序版本\": \"%s\",\n",PROGRAM_VERSION);
		printf("\"程序开始时间\": \"%s\",\n",start_time);
		printf("\"总运行时间\": \"%s\",\n",run_time_string);
		if (last_command_check == (time_t)0)
            printf("\"最近额外命令检查\": null,\n");
		else
			printf("\"最近额外命令检查\": \"%s\",\n",last_external_check_time);
		if (last_log_rotation==(time_t)0)
			printf("\"最近日志文件回滚\": null,\n");
		else
			printf("\"最近日志文件回滚\": \"%s\",\n",last_log_rotation_time);
        
		printf("\"icinga pid\": %d,\n",nagios_pid);
		printf("\"启用通知\": %s,\n",(enable_notifications==TRUE)?"true":"false");
		printf("\"执行服务检查\": %s,\n",(execute_service_checks==TRUE)?"true":"false");
		printf("\"接受的被动服务检查\": %s,\n",(accept_passive_service_checks==TRUE)?"true":"false");
		printf("\"执行主机检查\": %s,\n",(execute_host_checks==TRUE)?"true":"false");
		printf("\"接受的被动主机检查\": %s,\n",(accept_passive_host_checks==TRUE)?"true":"false");
		printf("\"启用事件处理\": %s,\n",(enable_event_handlers==TRUE)?"true":"false");
		printf("\"强迫服务\": %s,\n",(obsess_over_services==TRUE)?"true":"false");
		printf("\"强迫主机\": %s,\n",(obsess_over_hosts==TRUE)?"true":"false");
		printf("\"启用抖动检测\": %s,\n",(enable_flap_detection==TRUE)?"true":"false");
		printf("\"处理性能数据\": %s\n",(process_performance_data==TRUE)?"true":"false");
#ifdef PREDICT_FAILURES
		printf(",\"启用失败预测\": %s\n",(enable_failure_prediction==TRUE)?"true":"false");
#endif
#ifdef USE_OLDCRUD
		printf(",\"作为守护进程运行\": %s\n",(daemon_mode==TRUE)?"true":"false")
#endif
		printf("}\n");
	} else if (content_type == CSV_CONTENT) {
		/* csv header line */
		printf("%s程序版本%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s程序开始时间E%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s总运行时间%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s最近额外命令检查%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s最近日志文件回滚%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%sICINGA_PID%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s启用通知%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s执行服务检查%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s接受被动服务检查%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s执行主机检查%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s接受被动主机检查%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s启用事件处理D%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s强迫服务%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s强迫主机%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s启用抖动检查%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s处理性能数据%s", csv_data_enclosure, csv_data_enclosure);
#ifdef PREDICT_FAILURES
		printf("%s%s启用故障预测%s", csv_delimiter, csv_data_enclosure, csv_data_enclosure);
#endif
#ifdef USE_OLDCRUD
		printf("%s%s作为守护程序运行%s", csv_delimiter, csv_data_enclosure, csv_data_enclosure, csv_delimiter);
#endif
		printf("\n");

		/* csv data line */
		printf("%s%s%s%s", csv_data_enclosure, PROGRAM_VERSION, csv_data_enclosure, csv_delimiter);
		printf("%s%s%s%s", csv_data_enclosure, start_time, csv_data_enclosure, csv_delimiter);
		printf("%s%s%s%s", csv_data_enclosure, run_time_string, csv_data_enclosure, csv_delimiter);
		printf("%s%s%s%s", csv_data_enclosure, (last_command_check == (time_t)0) ? "无" : last_external_check_time, csv_data_enclosure, csv_delimiter);
		printf("%s%s%s%s", csv_data_enclosure, (last_log_rotation == (time_t)0) ? "无" : last_log_rotation_time, csv_data_enclosure, csv_delimiter);
		printf("%s%d%s%s", csv_data_enclosure, nagios_pid, csv_data_enclosure, csv_delimiter);
		printf("%s%s%s%s", csv_data_enclosure, (enable_notifications == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
		printf("%s%s%s%s", csv_data_enclosure, (execute_service_checks == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
		printf("%s%s%s%s", csv_data_enclosure, (accept_passive_service_checks == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
		printf("%s%s%s%s", csv_data_enclosure, (execute_host_checks == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
		printf("%s%s%s%s", csv_data_enclosure, (accept_passive_host_checks == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
		printf("%s%s%s%s", csv_data_enclosure, (enable_event_handlers == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
		printf("%s%s%s%s", csv_data_enclosure, (obsess_over_services == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
		printf("%s%s%s%s", csv_data_enclosure, (obsess_over_hosts == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
		printf("%s%s%s%s", csv_data_enclosure, (enable_flap_detection == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
		printf("%s%s%s", csv_data_enclosure, (process_performance_data == TRUE) ? "是" : "否", csv_data_enclosure);
#ifdef PREDICT_FAILURES
		printf("%s%s%s%s", csv_delimiter, csv_data_enclosure, (enable_failure_prediction == TRUE) ? "是" : "否", csv_data_enclosure);
#endif
#ifdef USE_OLDCRUD
		printf("%s%s%s%s", csv_delimiter, csv_data_enclosure, (daemon_mode == TRUE) ? "是" : "否", csv_data_enclosure);
#endif
		printf("\n");
	} else {
		printf("<br>\n");

		/* add export to csv, json, link */
		printf("<div class='csv_export_link'>");
		print_export_link(CSV_CONTENT, EXTINFO_CGI, NULL);
		print_export_link(JSON_CONTENT, EXTINFO_CGI, NULL);
		print_export_link(HTML_CONTENT, EXTINFO_CGI, NULL);
		printf("</div>");

		printf("<TABLE BORDER=0 CELLPADDING=20 align='center'>\n");
		printf("<TR><TD VALIGN=TOP>\n");

		printf("<DIV CLASS='dataTitle'>进程信息</DIV>\n");

		printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0 CLASS='data'>\n");
		printf("<TR><TD class='stateInfoTable1'>\n");
		printf("<TABLE BORDER=0>\n");

		/* program version */
		printf("<TR><TD CLASS='dataVar'>程序版本:</TD><TD CLASS='dataVal'>%s</TD></TR>\n", PROGRAM_VERSION);

		/* program start time */
		printf("<TR><TD CLASS='dataVar'>程序开始时间:</TD><TD CLASS='dataVal'>%s</TD></TR>\n", start_time);

		/* total running time */
		printf("<TR><TD CLASS='dataVar'>总运行时间:</TD><TD CLASS='dataVal'>%s</TD></TR>\n", run_time_string);

		/* last external check */
		printf("<TR><TD CLASS='dataVar'>最近额外命令检查:</TD><TD CLASS='dataVal'>%s</TD></TR>\n", (last_command_check == (time_t)0) ? "无" : last_external_check_time);

		/* last log file rotation */
		printf("<TR><TD CLASS='dataVar'>最近日志文件回滚:</TD><TD CLASS='dataVal'>%s</TD></TR>\n", (last_log_rotation == (time_t)0) ? "无" : last_log_rotation_time);

		/* PID */
		printf("<TR><TD CLASS='dataVar'>Icinga PID</TD><TD CLASS='dataVal'>%d</TD></TR>\n", nagios_pid);

		/* notifications enabled */
		printf("<TR><TD CLASS='dataVar'>启用通知?</TD><TD CLASS='dataVal'><DIV CLASS='notifications%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></TD></TR>\n", (enable_notifications == TRUE) ? "ENABLED" : "DISABLED", (enable_notifications == TRUE) ? "是" : "否");
		if (enable_notifications == FALSE)
			printf("<TR><TD CLASS='dataVar'>逾期禁用通知:</TD><TD CLASS='dataVal'>%s</TD></TR>\n", disable_notif_expire_time);
		else
			printf("<TR><TD CLASS='dataVar'>逾期禁用通知:</TD><TD CLASS='dataVal'><DIV CLASS='notificationsUNKNOWN'>&nbsp;&nbsp没有设置&nbsp;&nbsp;</DIV></TD></TR>\n");


		/* service check execution enabled */
		printf("<TR><TD CLASS='dataVar'>执行服务检查?</TD><TD CLASS='dataVal'><DIV CLASS='checks%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></TD></TR>\n", (execute_service_checks == TRUE) ? "ENABLED" : "DISABLED", (execute_service_checks == TRUE) ? "是" : "否");

		/* passive service check acceptance */
		printf("<TR><TD CLASS='dataVar'>接受被动服务检查?</TD><TD CLASS='dataVal'><DIV CLASS='checks%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></TD></TR>\n", (accept_passive_service_checks == TRUE) ? "ENABLED" : "DISABLED", (accept_passive_service_checks == TRUE) ? "是" : "否");

		/* host check execution enabled */
		printf("<TR><TD CLASS='dataVar'>执行主机检查?</TD><TD CLASS='dataVal'><DIV CLASS='checks%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></TD></TR>\n", (execute_host_checks == TRUE) ? "ENABLED" : "DISABLED", (execute_host_checks == TRUE) ? "是" : "否");

		/* passive host check acceptance */
		printf("<TR><TD CLASS='dataVar'>接受被动主机检查?</TD><TD CLASS='dataVal'><DIV CLASS='checks%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></TD></TR>\n", (accept_passive_host_checks == TRUE) ? "ENABLED" : "DISABLED", (accept_passive_host_checks == TRUE) ? "是" : "否");

		/* event handlers enabled */
		printf("<TR><TD CLASS='dataVar'>启用事件处理?</TD><TD CLASS='dataVal'>%s</TD></TR>\n", (enable_event_handlers == TRUE) ? "是" : "否");

		/* obsessing over services */
		printf("<TR><TD CLASS='dataVar'>强迫服务?</TD><TD CLASS='dataVal'>%s</TD></TR>\n", (obsess_over_services == TRUE) ? "是" : "否");

		/* obsessing over hosts */
		printf("<TR><TD CLASS='dataVar'>强迫主机?</TD><TD CLASS='dataVal'>%s</TD></TR>\n", (obsess_over_hosts == TRUE) ? "是" : "否");

		/* flap detection enabled */
		printf("<TR><TD CLASS='dataVar'>启用抖动监测?</TD><TD CLASS='dataVal'>%s</TD></TR>\n", (enable_flap_detection == TRUE) ? "是" : "否");

#ifdef PREDICT_FAILURES
		/* failure prediction enabled */
		printf("<TR><TD CLASS='dataVar'>启用故障预测?</TD><TD CLASS='dataVal'>%s</TD></TR>\n", (enable_failure_prediction == TRUE) ? "是" : "否");
#endif

		/* process performance data */
		printf("<TR><TD CLASS='dataVar'>处理性能数据?</TD><TD CLASS='dataVal'>%s</TD></TR>\n", (process_performance_data == TRUE) ? "是" : "否");

		/* Notifications disabled will expire? */
		if(enable_notifications == TRUE && disable_notifications_expire_time > 0)
			printf("<TR><TD CLASS='dataVar'>通知?</TD><TD CLASS='dataVal'>%s</TD></TR>\n", (process_performance_data == TRUE) ? "是" : "否");


#ifdef USE_OLDCRUD
		/* daemon mode */
		printf("<TR><TD CLASS='dataVar'>作为守护进程运行?</TD><TD CLASS='dataVal'>%s</TD></TR>\n", (daemon_mode == TRUE) ? "是" : "否");
#endif

		printf("</TABLE>\n");
		printf("</TD></TR>\n");
		printf("</TABLE>\n");


		printf("</TD><TD VALIGN=TOP>\n");

		printf("<DIV CLASS='commandTitle'>进程命令</DIV>\n");

		printf("<TABLE BORDER=1 CELLPADDING=0 CELLSPACING=0 CLASS='command'>\n");
		printf("<TR><TD>\n");

		printf("<TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 CLASS='command'>\n");

#ifndef DUMMY_INSTALL
			printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='关闭Icinga进程' TITLE='关闭Icinga进程'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>关闭Icinga进程</a></td></tr>\n", url_images_path, STOP_ICON, CMD_CGI, CMD_SHUTDOWN_PROCESS);
			printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='重启Icinga进程' TITLE='重启Icinga进程'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>重启Icinga进程</a></td></tr>\n", url_images_path, RESTART_ICON, CMD_CGI, CMD_RESTART_PROCESS);
#endif

			if (enable_notifications == TRUE)
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='禁用通知' TITLE='禁用通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>禁用通知</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_NOTIFICATIONS);
			else
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='启用通知' TITLE='启用通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>启用通知</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_NOTIFICATIONS);

			if (execute_service_checks == TRUE)
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='停止执行服务检查' TITLE='停止执行服务检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>停止执行服务检查</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_STOP_EXECUTING_SVC_CHECKS);
			else
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='开始执行服务检查' TITLE='开始执行服务检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>开始执行服务检查</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_START_EXECUTING_SVC_CHECKS);

			if (accept_passive_service_checks == TRUE)
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='停止接受被动服务检查' TITLE='停止接受被动服务检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>停止接受被动服务检查</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_STOP_ACCEPTING_PASSIVE_SVC_CHECKS);
			else
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='开始接受被动服务检查' TITLE='开始接受被动服务检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>开始接受被动服务检查</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_START_ACCEPTING_PASSIVE_SVC_CHECKS);

			if (execute_host_checks == TRUE)
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='停止执行主机检查' TITLE='停止执行主机检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>停止执行主机检查</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_STOP_EXECUTING_HOST_CHECKS);
			else
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='开始执行主机检查' TITLE='开始执行主机检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>开始执行主机检查</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_START_EXECUTING_HOST_CHECKS);

			if (accept_passive_host_checks == TRUE)
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='停止接受被动主机检查' TITLE='停止接受被动主机检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>停止接受被动主机检查</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_STOP_ACCEPTING_PASSIVE_HOST_CHECKS);
			else
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='开始接受被动主机检查' TITLE='开始接受被动主机检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>开始接受被动主机检查</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_START_ACCEPTING_PASSIVE_HOST_CHECKS);

			if (enable_event_handlers == TRUE)
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='禁用事件处理' TITLE='禁用事件处理'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>禁用事件处理</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_EVENT_HANDLERS);
			else
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='启用事件处理' TITLE='启用事件处理'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>启用事件处理</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_EVENT_HANDLERS);

			if (obsess_over_services == TRUE)
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='停止强迫服务' TITLE='停止强迫服务'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>停止强迫服务</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_STOP_OBSESSING_OVER_SVC_CHECKS);
			else
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='开始强迫服务' TITLE='开始强迫服务'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>开始强迫服务</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_START_OBSESSING_OVER_SVC_CHECKS);

			if (obsess_over_hosts == TRUE)
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='停止强迫主机' TITLE='停止强迫主机'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>停止强迫主机</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_STOP_OBSESSING_OVER_HOST_CHECKS);
			else
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='开始强迫主机' TITLE='开始强迫主机'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>开始强迫主机</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_START_OBSESSING_OVER_HOST_CHECKS);

			if (enable_flap_detection == TRUE)
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='禁用抖动监测' TITLE='禁用抖动监测'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>禁用抖动监测</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_FLAP_DETECTION);
			else
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='启用抖动监测' TITLE='启用抖动监测'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>启用抖动监测</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_FLAP_DETECTION);

#ifdef PREDICT_FAILURES
			if (enable_failure_prediction == TRUE)
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='禁用故障预测' TITLE='禁用故障预测'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>禁用故障预测</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_FAILURE_PREDICTION);
			else
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='启用故障预测' TITLE='启用故障预测'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>启用故障预测</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_FAILURE_PREDICTION);
#endif
			if (process_performance_data == TRUE)
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='禁用性能数据' TITLE='禁用性能数据'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>禁用性能数据</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_PERFORMANCE_DATA);
			else
				printf("<TR CLASS='command'><TD><img src='%s%s' border=0 ALT='启用性能数据' TITLE='启用性能数据'></td><td CLASS='command'><a href='%s?cmd_typ=%d'>启用性能数据</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_PERFORMANCE_DATA);

		printf("</TABLE>\n");

		printf("</TD></TR>\n");
		printf("</TABLE>\n");

		printf("</TD></TR></TABLE>\n");
	}
}

void show_host_info(void) {
	hoststatus *temp_hoststatus;
	host *temp_host;
	char date_time[MAX_DATETIME_LENGTH];
	char state_duration[48];
	char status_age[48];
	char state_string[MAX_INPUT_BUFFER];
	char *bg_class = "";
	char *buf = NULL;
	int days;
	int hours;
	int minutes;
	int seconds;
	time_t current_time;
	time_t ts_state_duration;
	time_t ts_state_age;
	int duration_error = FALSE;


	/* get host info */
	temp_host = find_host(host_name);

	/* make sure the user has rights to view host information */
	if (is_authorized_for_host(temp_host, &current_authdata) == FALSE) {
		print_generic_error_message("很显然您无权查看该主机信息...","如果您认为这是一个错误, 请检查访问CGI的HTTP服务器身份验证要求,并检查您的CGI配置文件的授权选项.", 0);
		return;
	}

	/* get host status info */
	temp_hoststatus = find_hoststatus(host_name);

	/* make sure host information exists */
	if (temp_host == NULL) {
		print_generic_error_message("错误: 主机不存在!", NULL, 0);
		return;
	}
	if (temp_hoststatus == NULL) {
		print_generic_error_message("错误: 主机状态信息不存在!", NULL, 0);
		return;
	}

	/* calculate state duration */
	current_time = time(NULL);
	ts_state_duration = 0;
	duration_error = FALSE;
	if (temp_hoststatus->last_state_change == (time_t)0) {
		if (program_start > current_time)
			duration_error = TRUE;
		else
			ts_state_duration = current_time - program_start;
	} else {
		if (temp_hoststatus->last_state_change > current_time)
			duration_error = TRUE;
		else
			ts_state_duration = current_time - temp_hoststatus->last_state_change;
	}
	get_time_breakdown((unsigned long)ts_state_duration, &days, &hours, &minutes, &seconds);
	if (duration_error == TRUE)
		snprintf(state_duration, sizeof(state_duration) - 1, "???");
	else
		snprintf(state_duration, sizeof(state_duration) - 1, "%2d天%2d时%2d分%2d秒%s", days, hours, minutes, seconds, (temp_hoststatus->last_state_change == (time_t)0) ? "+" : "");
	state_duration[sizeof(state_duration) - 1] = '\x0';

	/* calculate state age */
	ts_state_age = 0;
	duration_error = FALSE;
	if (temp_hoststatus->last_check > current_time)
		duration_error = TRUE;
	else
		/*t=current_time-temp_hoststatus->last_check;*/
		ts_state_age = current_time - temp_hoststatus->last_update;
	get_time_breakdown((unsigned long)ts_state_age, &days, &hours, &minutes, &seconds);
	if (duration_error == TRUE)
		snprintf(status_age, sizeof(status_age) - 1, "???");
	else if (temp_hoststatus->last_check == (time_t)0)
		snprintf(status_age, sizeof(status_age) - 1, "无");
	else
		snprintf(status_age, sizeof(status_age) - 1, "%2d天%2d时%2d分%2d秒", days, hours, minutes, seconds);
	status_age[sizeof(status_age)-1] = '\x0';

	/* first, we mark and color it as maintenance if that is preferred */
	if (suppress_maintenance_downtime == TRUE && temp_hoststatus->scheduled_downtime_depth > 0) {
		if (temp_hoststatus->status == HOST_UP)
			strcpy(state_string, "运行 (维护)");
		else if (temp_hoststatus->status == HOST_DOWN)
			strcpy(state_string, "宕机 (维护)");
		else if (temp_hoststatus->status == HOST_UNREACHABLE)
			strcpy(state_string, "不可达 (维护)");
		else //catch any other state (just in case)
			strcpy(state_string, "维护");
		bg_class = "hostDOWNTIME";

		/* otherwise we mark and color it with its appropriate state */
	} else if (temp_hoststatus->status == HOST_UP) {
		strcpy(state_string, "运行");
		bg_class = "hostUP";
	} else if (temp_hoststatus->status == HOST_DOWN) {
		strcpy(state_string, "宕机");
		bg_class = "hostDOWN";
	} else if (temp_hoststatus->status == HOST_UNREACHABLE) {
		strcpy(state_string, "不可达");
		bg_class = "hostUNREACHABLE";
	}

	if (content_type == JSON_CONTENT) {
		printf("\"主机信息\": {\n");
		printf("\"主机名称\": \"%s\",\n", json_encode(host_name));
		printf("\"主机显示名称\": \"%s\",\n", (temp_host->display_name != NULL) ? json_encode(temp_host->display_name) : json_encode(host_name));
		if (temp_hoststatus->has_been_checked == FALSE)
			printf("\"完成检查\": false\n");
		else {
			printf("\"完成检查\": true,\n");
			printf("\"状态\": \"%s\",\n", state_string);
			printf("\"状态类型\": \"%s\",\n", (temp_hoststatus->state_type == HARD_STATE) ? "硬" : "软");
			if (duration_error == TRUE)
				printf("\"状态持续时间\": false,\n");
			else
				printf("\"状态持续时间\": \"%s\",\n", state_duration);
			printf("\"状态的持续时间(秒)\": %lu,\n", (unsigned long)ts_state_duration);
			if (temp_hoststatus->long_plugin_output != NULL)
				printf("\"状态信息\": \"%s\\n%s\",\n", json_encode(temp_hoststatus->plugin_output), json_encode(temp_hoststatus->long_plugin_output));
			else if (temp_hoststatus->plugin_output != NULL)
				printf("\"状态信息\": \"%s\",\n", json_encode(temp_hoststatus->plugin_output));
			else
				printf("\"状态信息\": null,\n");
			if (temp_hoststatus->perf_data == NULL)
				printf("\"性能数据\": null,\n");
			else
				printf("\"性能数据\": \"%s\",\n", json_encode(temp_hoststatus->perf_data));
			printf("\"当前尝试\": %d,\n", temp_hoststatus->current_attempt);
			printf("\"最大尝试\": %d,\n", temp_hoststatus->max_attempts);

			if (temp_hoststatus->checks_enabled == TRUE)
				printf("\"检查类型\": \"主动\",\n");
			else if (temp_hoststatus->accept_passive_host_checks == TRUE)
				printf("\"检查类型\": \"被动\",\n");
			else
				printf("\"检查类型\": \"禁用\",\n");

			get_time_string(&temp_hoststatus->last_check, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			printf("\"最近检查时间\": \"%s\",\n", date_time);

			if (temp_hoststatus->checks_enabled == TRUE)
				printf("\"检查延时\": %.3f,\n", temp_hoststatus->latency);
			else
				printf("\"检查延时\": null,\n");

			printf("\"检查持续时间\": %.3f,\n", temp_hoststatus->execution_time);

			get_time_string(&temp_hoststatus->next_check, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			if (temp_hoststatus->checks_enabled && temp_hoststatus->next_check != (time_t)0 && temp_hoststatus->should_be_scheduled == TRUE)
				printf("\"安排下一次主动检查\": \"%s\",\n", date_time);
			else
				printf("\"安排下一次主动检查\": null,\n");

			get_time_string(&temp_hoststatus->last_state_change, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			if (temp_hoststatus->last_state_change == (time_t)0)
				printf("\"最近状态变化\": null,\n");
			else
				printf("\"最近状态变化\": \"%s\",\n", date_time);

			get_time_string(&temp_hoststatus->last_notification, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			if (temp_hoststatus->last_notification == (time_t)0)
				printf("\"last_notification\": null,\n");
			else
				printf("\"last_notification\": \"%s\",\n", date_time);
			printf("\"current_notification_number\": %d,\n", temp_hoststatus->current_notification_number);
			if (temp_hoststatus->flap_detection_enabled == FALSE || enable_flap_detection == FALSE)
				printf("\"host_is_flapping\": null,\n");
			else
				printf("\"host_is_flapping\": %s,\n", (temp_hoststatus->is_flapping == TRUE) ? "true" : "false");
			printf("\"flapping_percent_state_change\": %3.2f,\n", temp_hoststatus->percent_state_change);
			printf("\"host_in_scheduled_downtime\": %s,\n", (temp_hoststatus->scheduled_downtime_depth > 0) ? "true" : "false");
			printf("\"host_has_been_acknowledged\": %s,\n", (temp_hoststatus->problem_has_been_acknowledged == TRUE) ? "true" : "false");

			get_time_string(&temp_hoststatus->last_update, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			printf("\"last_update\": \"%s\",\n", date_time);

			printf("\"modified_attributes\": \"");
			print_modified_attributes(JSON_CONTENT, EXTINFO_CGI, temp_hoststatus->modified_attributes);
			printf("\",\n");

			printf("\"active_checks_enabled\": %s,\n", (temp_hoststatus->checks_enabled == TRUE) ? "true" : "false");
			printf("\"passive_checks_enabled\": %s,\n", (temp_hoststatus->accept_passive_host_checks == TRUE) ? "true" : "false");
			printf("\"obsess_over_host\": %s,\n", (temp_hoststatus->obsess_over_host == TRUE) ? "true" : "false");
			printf("\"notifications_enabled\": %s,\n", (temp_hoststatus->notifications_enabled == TRUE) ? "true" : "false");
			printf("\"event_handler_enabled\": %s,\n", (temp_hoststatus->event_handler_enabled == TRUE) ? "true" : "false");
			printf("\"flap_detection_enabled\": %s\n", (temp_hoststatus->flap_detection_enabled == TRUE) ? "true" : "false");
			if (is_authorized_for_read_only(&current_authdata) == FALSE || is_authorized_for_comments_read_only(&current_authdata) == TRUE) {

				/* display comments */
				printf(",\n");
				show_comments(HOST_COMMENT);

				/* display downtimes */
				printf(",\n");
				show_downtime(HOST_DOWNTIME);
			}
			printf(" }\n");
		}
	} else {
		printf("<TABLE BORDER=0 CELLPADDING=0 WIDTH='100%%' align='center'>\n");
		printf("<TR>\n");

		printf("<TD ALIGN=CENTER VALIGN=TOP CLASS='stateInfoPanel'>\n");

		printf("<DIV CLASS='dataTitle'>主机状态信息</DIV>\n");

		if (temp_hoststatus->has_been_checked == FALSE)
			printf("<DIV ALIGN=CENTER>该主机尚未检查，因此状态信息不存在.</DIV>\n");

		else {

			printf("<TABLE BORDER=0>\n");
			printf("<TR><TD>\n");

			printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0>\n");
			printf("<TR><TD class='stateInfoTable1'>\n");
			printf("<TABLE BORDER=0>\n");

			printf("<TR><TD CLASS='dataVar'>主机状态:</td><td CLASS='dataVal'><DIV CLASS='%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV>&nbsp;(为 %s)%s</td></tr>\n", bg_class, state_string, state_duration, (temp_hoststatus->problem_has_been_acknowledged == TRUE) ? "&nbsp;&nbsp;(已确认)" : "");

			printf("<TR><TD CLASS='dataVar' VALIGN='top'>状态信息:</td><td CLASS='dataVal'>%s", (temp_hoststatus->plugin_output == NULL) ? "" : html_encode(temp_hoststatus->plugin_output, TRUE));
			if (enable_splunk_integration == TRUE) {
				printf("&nbsp;&nbsp;");
				dummy = asprintf(&buf, "%s %s", temp_host->name, temp_hoststatus->plugin_output);
				buf[sizeof(buf) - 1] = '\x0';
				display_splunk_generic_url(buf, 1);
				free(buf);
			}
			if (temp_hoststatus->long_plugin_output != NULL)
				printf("<BR>%s", html_encode(temp_hoststatus->long_plugin_output, TRUE));
			printf("</TD></TR>\n");

			printf("<TR><TD CLASS='dataVar' VALIGN='top'>性能数据:</td><td CLASS='dataVal'>%s</td></tr>\n", (temp_hoststatus->perf_data == NULL) ? "" : html_encode(temp_hoststatus->perf_data, TRUE));

			printf("<TR><TD CLASS='dataVar'>当前尝试:</TD><TD CLASS='dataVal'>%d/%d", temp_hoststatus->current_attempt, temp_hoststatus->max_attempts);
			printf("&nbsp;&nbsp;(%s状态)</TD></TR>\n", (temp_hoststatus->state_type == HARD_STATE) ? "硬" : "软");

			get_time_string(&temp_hoststatus->last_check, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			printf("<TR><TD CLASS='dataVar'>最近检查时间:</td><td CLASS='dataVal'>%s</td></tr>\n", date_time);

			if (temp_hoststatus->checks_enabled == TRUE)
				printf("<TR><TD CLASS='dataVar'>检查类型:</TD><TD CLASS='dataVal'><A HREF='%s?type=command&host=%s&expand=%s'>主动</A></TD></TR>\n", CONFIG_CGI, host_name, url_encode(temp_host->host_check_command));
			else if (temp_hoststatus->accept_passive_host_checks == TRUE)
				printf("<TR><TD CLASS='dataVar'>检查类型:</TD><TD CLASS='dataVal'>被动</TD></TR>\n");
			else
				printf("<TR><TD CLASS='dataVar'>检查类型:</TD><TD CLASS='dataVal'>禁用</TD></TR>\n");

			printf("<TR><TD CLASS='dataVar' NOWRAP>检查延迟／持续时间:</TD><TD CLASS='dataVal'>");
			if (temp_hoststatus->checks_enabled == TRUE)
				printf("%.3f", temp_hoststatus->latency);
			else
				printf("无");
			printf("&nbsp;/&nbsp;%.3f 秒", temp_hoststatus->execution_time);
			printf("</TD></TR>\n");

			get_time_string(&temp_hoststatus->next_check, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			printf("<TR><TD CLASS='dataVar'>安排下一次主动检查:&nbsp;&nbsp;</TD><TD CLASS='dataVal'>%s</TD></TR>\n", (temp_hoststatus->checks_enabled && temp_hoststatus->next_check != (time_t)0 && temp_hoststatus->should_be_scheduled == TRUE) ? date_time : "无");

			get_time_string(&temp_hoststatus->last_state_change, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			printf("<TR><TD CLASS='dataVar'>最近状态变化:</td><td CLASS='dataVal'>%s</td></tr>\n", (temp_hoststatus->last_state_change == (time_t)0) ? "无" : date_time);

			get_time_string(&temp_hoststatus->last_notification, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			printf("<TR><TD CLASS='dataVar'>最近通知:</td><td CLASS='dataVal'>%s&nbsp;(通知 %d)</td></tr>\n", (temp_hoststatus->last_notification == (time_t)0) ? "无" : date_time, temp_hoststatus->current_notification_number);

			printf("<TR><TD CLASS='dataVar'>主机抖动?</td><td CLASS='dataVal'>");
			if (temp_hoststatus->flap_detection_enabled == FALSE || enable_flap_detection == FALSE)
				printf("无");
			else
				printf("<DIV CLASS='%sflapping'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV>&nbsp;(%3.2f%% 状态变化)", (temp_hoststatus->is_flapping == TRUE) ? "" : "not", (temp_hoststatus->is_flapping == TRUE) ? "是" : "否", temp_hoststatus->percent_state_change);
			printf("</td></tr>\n");

			printf("<TR><TD CLASS='dataVar'>在安排宕机中?</td><td CLASS='dataVal'><DIV CLASS='downtime%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></td></tr>\n", (temp_hoststatus->scheduled_downtime_depth > 0) ? "ACTIVE" : "INACTIVE", (temp_hoststatus->scheduled_downtime_depth > 0) ? "是" : "否");


			get_time_string(&temp_hoststatus->last_update, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			printf("<TR><TD CLASS='dataVar'>最近更新:</td><td CLASS='dataVal'>%s&nbsp;&nbsp;(%s ago)</td></tr>\n", (temp_hoststatus->last_update == (time_t)0) ? "无" : date_time, status_age);

			printf("<TR><TD CLASS='dataVar'>属性修改:</td><td CLASS='dataVal'>");
			print_modified_attributes(HTML_CONTENT, EXTINFO_CGI, temp_hoststatus->modified_attributes);
			printf("</td></tr>\n");

			printf("<TR><TD CLASS='dataVar'>Executed Command:</TD><TD CLASS='dataVal'><A HREF='%s?type=command&host=%s&expand=%s'>Command Expander</A></TD></TR>\n", CONFIG_CGI, url_encode(host_name), url_encode(temp_host->host_check_command));

			printf("</TABLE>\n");
			printf("</TD></TR>\n");
			printf("</TABLE>\n");

			printf("</TD></TR>\n");
			printf("<TR><TD>\n");

			printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0 align='left'>\n");
			printf("<TR><TD class='stateInfoTable2'>\n");
			printf("<TABLE BORDER=0>\n");

			if ((temp_host->host_check_command) && (*temp_host->host_check_command != '\0'))
				printf("<TR><TD CLASS='dataVar'><A HREF='%s?type=command&expand=%s'>主动检查:</A></TD><TD CLASS='dataVal'><DIV CLASS='checks%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></TD></TR>\n", CONFIG_CGI, url_encode(temp_host->host_check_command), (temp_hoststatus->checks_enabled == TRUE) ? "ENABLED" : "DISABLED", (temp_hoststatus->checks_enabled == TRUE) ? "启用" : "禁用");
			else printf("<TR><TD CLASS='dataVar'>主动检查:</TD><TD CLASS='dataVal'><DIV CLASS='checks%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></TD></TR>\n", (temp_hoststatus->checks_enabled == TRUE) ? "ENABLED" : "DISABLED", (temp_hoststatus->checks_enabled == TRUE) ? "启用" : "禁用");

			printf("<TR><TD CLASS='dataVar'>被动检查:</TD><td CLASS='dataVal'><DIV CLASS='checks%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></TD></TR>\n", (temp_hoststatus->accept_passive_host_checks == TRUE) ? "ENABLED" : "DISABLED", (temp_hoststatus->accept_passive_host_checks) ? "启用" : "禁用");

			printf("<TR><TD CLASS='dataVar'>强迫:</TD><td CLASS='dataVal'><DIV CLASS='checks%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></TD></TR>\n", (temp_hoststatus->obsess_over_host == TRUE) ? "ENABLED" : "DISABLED", (temp_hoststatus->obsess_over_host) ? "启用" : "禁用");

			printf("<TR><TD CLASS='dataVar'>通知:</td><td CLASS='dataVal'><DIV CLASS='notifications%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></td></tr>\n", (temp_hoststatus->notifications_enabled) ? "ENABLED" : "DISABLED", (temp_hoststatus->notifications_enabled) ? "启用" : "禁用");

			if ((temp_host->event_handler) && (*temp_host->event_handler != '\0'))
				printf("<TR><TD CLASS='dataVar'><A HREF='%s?type=command&expand=%s'>事件处理:</A></td><td CLASS='dataVal'><DIV CLASS='eventhandlers%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></td></tr>\n", CONFIG_CGI, url_encode(temp_host->event_handler), (temp_hoststatus->event_handler_enabled) ? "ENABLED" : "DISABLED", (temp_hoststatus->event_handler_enabled) ? "启用" : "禁用");
			else printf("<TR><TD CLASS='dataVar'>事件处理:</td><td CLASS='dataVal'><DIV CLASS='eventhandlers%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></td></tr>\n", (temp_hoststatus->event_handler_enabled) ? "ENABLED" : "DISABLED", (temp_hoststatus->event_handler_enabled) ? "启用" : "禁用");


			printf("<TR><TD CLASS='dataVar'>抖动检测:</td><td CLASS='dataVal'><DIV CLASS='flapdetection%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></td></tr>\n", (temp_hoststatus->flap_detection_enabled == TRUE) ? "ENABLED" : "DISABLED", (temp_hoststatus->flap_detection_enabled == TRUE) ? "启用" : "禁用");

			printf("</TABLE>\n");
			printf("</TD></TR>\n");
			printf("</TABLE>\n");

			printf("</TD></TR>\n");
			printf("</TABLE>\n");
		}

		printf("</TD>\n");

		printf("<TD ALIGN=CENTER VALIGN=TOP>\n");
		printf("<TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0><TR>\n");

		printf("<TD ALIGN=CENTER VALIGN=TOP CLASS='commandPanel'>\n");

		printf("<DIV CLASS='commandTitle'>主机命令</DIV>\n");

		printf("<TABLE BORDER='1' CELLPADDING=0 CELLSPACING=0><TR><TD>\n");

		if (is_authorized_for_read_only(&current_authdata) == FALSE) {

			printf("<TABLE BORDER=0 CELLSPACING=0 CELLPADDING=0 CLASS='command'>\n");
#ifdef USE_STATUSMAP
			printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='在地图上定位主机' TITLE='在地图上定位主机'></td><td CLASS='command'><a href='%s?host=%s'>在地图上定位主机</a></td></tr>\n", url_images_path, STATUSMAP_ICON, STATUSMAP_CGI, url_encode(host_name));
#endif
			if (temp_hoststatus->checks_enabled == TRUE) {
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='禁用该主机主动检查' TITLE='禁用该主机主动检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>禁用该主机主动检查</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_HOST_CHECK, url_encode(host_name));
			} else
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='启用该主机主动检查' TITLE='启用该主机主动检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>启用该主机主动检查</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_HOST_CHECK, url_encode(host_name));
			printf("<tr CLASS='data'><td><img src='%s%s' border=0 ALT='重新安排下次主机检查' TITLE='重新安排下次主机检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s%s'>重新安排下次主机检查</a></td></tr>\n", url_images_path, DELAY_ICON, CMD_CGI, CMD_SCHEDULE_HOST_CHECK, url_encode(host_name), (temp_hoststatus->checks_enabled == TRUE) ? "&force_check" : "");

			if (temp_hoststatus->accept_passive_host_checks == TRUE) {
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='提交该主机被动检查结果' TITLE='提交该主机被动检查结果'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>提交该主机被动检查结果</a></td></tr>\n", url_images_path, PASSIVE_ICON, CMD_CGI, CMD_PROCESS_HOST_CHECK_RESULT, url_encode(host_name));
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='停止该主机接受被动检查' TITLE='停止该主机接受被动检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>停止该主机接受被动检查</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_PASSIVE_HOST_CHECKS, url_encode(host_name));
			} else
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='开始该主机接受被动检查' TITLE='开始该主机接受被动检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>开始该主机接受被动检查</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_PASSIVE_HOST_CHECKS, url_encode(host_name));

			if (temp_hoststatus->obsess_over_host == TRUE)
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='停止强迫该主机' TITLE='停止强迫该主机'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>停止强迫该主机</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_STOP_OBSESSING_OVER_HOST, url_encode(host_name));
			else
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='开始强迫该主机' TITLE='开始强迫该主机'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>开始强迫该主机</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_START_OBSESSING_OVER_HOST, url_encode(host_name));

			if (temp_hoststatus->status == HOST_DOWN || temp_hoststatus->status == HOST_UNREACHABLE) {
				if (temp_hoststatus->problem_has_been_acknowledged == FALSE)
					printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='确认该主机问题' TITLE='确认该主机问题'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>确认该主机问题</a></td></tr>\n", url_images_path, ACKNOWLEDGEMENT_ICON, CMD_CGI, CMD_ACKNOWLEDGE_HOST_PROBLEM, url_encode(host_name));
				else
					printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='移除故障确认' TITLE='移除故障确认'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>移除故障确认</a></td></tr>\n", url_images_path, REMOVE_ACKNOWLEDGEMENT_ICON, CMD_CGI, CMD_REMOVE_HOST_ACKNOWLEDGEMENT, url_encode(host_name));
			}

			if (temp_hoststatus->notifications_enabled == TRUE)
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='禁用该主机通知' TITLE='禁用该主机通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>禁用该主机通知</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_HOST_NOTIFICATIONS, url_encode(host_name));
			else
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='启用该主机通知' TITLE='启用该主机通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>启用该主机通知</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_HOST_NOTIFICATIONS, url_encode(host_name));

			printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='发送自定义通知' TITLE='发送自定义通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>发送自定义通知</a></td></tr>\n", url_images_path, NOTIFICATION_ICON, CMD_CGI, CMD_SEND_CUSTOM_HOST_NOTIFICATION, url_encode(host_name));

			if (temp_hoststatus->status != HOST_UP)
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='延迟下一次主机通知' TITLE='延迟下一次主机通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>延迟下一次主机通知</a></td></tr>\n", url_images_path, DELAY_ICON, CMD_CGI, CMD_DELAY_HOST_NOTIFICATION, url_encode(host_name));

				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='安排该主机宕机时间' TITLE='安排该主机宕机时间'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>安排该主机宕机时间</a></td></tr>\n", url_images_path, DOWNTIME_ICON, CMD_CGI, CMD_SCHEDULE_HOST_DOWNTIME, url_encode(host_name));

				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='移除该主机和所有服务宕机时间' TITLE='移除该主机和所有服务宕机时间'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>移除该主机和所有服务宕机时间</a></td></tr>\n", url_images_path, DOWNTIME_ICON, CMD_CGI, CMD_SCHEDULE_HOST_SVC_DOWNTIME, url_encode(host_name));

				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='禁用该主机上的所有服务通知' TITLE='禁用该主机上的所有服务通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>禁用该主机上的所有服务通知</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DEL_DOWNTIME_BY_HOST_NAME, url_encode(host_name));

				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='禁用该主机上的所有服务通知' TITLE='禁用该主机上的所有服务通知'></td><td CLASS='command' NOWRAP><a href='%s?cmd_typ=%d&host=%s'>禁用该主机上的所有服务通知</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_HOST_SVC_NOTIFICATIONS, url_encode(host_name));

				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='启用该主机上所有服务通知' TITLE='启用该主机上所有服务通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>启用该主机上所有服务通知</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_HOST_SVC_NOTIFICATIONS, url_encode(host_name));

				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='安排该主机上所有服务检查' TITLE='安排该主机上所有服务检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>安排该主机上所有服务检查</a></td></tr>\n", url_images_path, DELAY_ICON, CMD_CGI, CMD_SCHEDULE_HOST_SVC_CHECKS, url_encode(host_name));

				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='禁用该主机上所有服务检查' TITLE='禁用该主机上所有服务检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>禁用该主机上所有服务检查</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_HOST_SVC_CHECKS, url_encode(host_name));

			printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='启用该主机上所有服务检查' TITLE='启用该主机上所有服务检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>启用该主机上所有服务检查</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_HOST_SVC_CHECKS, url_encode(host_name));

			if (temp_hoststatus->event_handler_enabled == TRUE)
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='禁用该主机事件处理' TITLE='禁用该主机事件处理'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>禁用该主机事件处理</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_HOST_EVENT_HANDLER, url_encode(host_name));
			else
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='启用该主机事件处理' TITLE='启用该主机事件处理'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>启用该主机事件处理</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_HOST_EVENT_HANDLER, url_encode(host_name));
			if (temp_hoststatus->flap_detection_enabled == TRUE)
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='禁用该主机抖动检测' TITLE='禁用该主机抖动检测'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>禁用该主机抖动检测</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_HOST_FLAP_DETECTION, url_encode(host_name));
			else
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='启用该主机抖动检测' TITLE='启用该主机抖动检测'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>启用该主机抖动检测</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_HOST_FLAP_DETECTION, url_encode(host_name));

			printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='添加新主机注释' TITLE='添加新主机注释'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s'>", url_images_path, COMMENT_ICON, CMD_CGI, CMD_ADD_HOST_COMMENT, (display_type == DISPLAY_COMMENTS) ? "" : url_encode(host_name));
			printf("添加新主机注释</a></td>");

            /* allow modified attributes to be reset */
			printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='重置属性修改' TITLE='重置属性修改'></td><td CLASS='command'><a href='%s?cmd_typ=%d&attr=%d&host=%s'>", url_images_path, DISABLED_ICON, CMD_CGI, CMD_CHANGE_HOST_MODATTR, MODATTR_NONE, (display_type == DISPLAY_COMMENTS) ? "" : url_encode(host_name));
            printf("重置修改的属性</a></td>");

			printf("</TABLE>\n");
		} else {
			print_generic_error_message("您的帐户没有权限执行命令.", NULL, 0);
		}
		printf("</TD></TR></TABLE>\n");

		printf("</TD>\n");

		printf("</TR>\n");
		printf("</TABLE></TR>\n");

		printf("<TR>\n");

		printf("<TD COLSPAN=2 VALIGN=TOP CLASS='commentPanel'>\n");

		if (is_authorized_for_read_only(&current_authdata) == FALSE || is_authorized_for_comments_read_only(&current_authdata) == TRUE) {
			/* display comments */
			show_comments(HOST_COMMENT);
			printf("<BR>");
			/* display downtimes */
			show_downtime(HOST_DOWNTIME);
		}

		printf("</TD>\n");

		printf("</TR>\n");
		printf("</TABLE>\n");
	}

	return;
}

void show_service_info(void) {
	service *temp_service;
	host *temp_host;
	char date_time[MAX_DATETIME_LENGTH];
	char status_age[48];
	char state_duration[48];
	servicestatus *temp_svcstatus;
	char state_string[MAX_INPUT_BUFFER];
	char *bg_class = "";
	char *buf = NULL;
	int days;
	int hours;
	int minutes;
	int seconds;
	time_t ts_state_duration = 0L;
	time_t ts_state_age = 0L;
	time_t current_time;
	int duration_error = FALSE;

	/* get host info */
	temp_host = find_host(host_name);

	/* find the service */
	temp_service = find_service(host_name, service_desc);

	/* make sure the user has rights to view service information */
	if (is_authorized_for_service(temp_service, &current_authdata) == FALSE) {

		print_generic_error_message("很显然您没有权限查看该服务信息...","如果您认为这是一个错误, 请检查访问CGI的HTTP服务器身份验证要求,并检查您的CGI配置文件的授权选项.", 0);

		return;
	}

	/* get service status info */
	temp_svcstatus = find_servicestatus(host_name, service_desc);

	/* make sure service information exists */
	if (temp_service == NULL) {
		print_generic_error_message("错误: 服务不存在!", NULL, 0);
		return;
	}
	if (temp_svcstatus == NULL) {
		print_generic_error_message("错误: 服务状态不存在!", NULL, 0);
		return;
	}


	current_time = time(NULL);
	duration_error = FALSE;
	if (temp_svcstatus->last_state_change == (time_t)0) {
		if (program_start > current_time)
			duration_error = TRUE;
		else
			ts_state_duration = current_time - program_start;
	} else {
		if (temp_svcstatus->last_state_change > current_time)
			duration_error = TRUE;
		else
			ts_state_duration = current_time - temp_svcstatus->last_state_change;
	}
	get_time_breakdown((unsigned long)ts_state_duration, &days, &hours, &minutes, &seconds);
	if (duration_error == TRUE)
		snprintf(state_duration, sizeof(state_duration) - 1, "???");
	else
		snprintf(state_duration, sizeof(state_duration) - 1, "%2d天%2d时%2d分%2d秒%s", days, hours, minutes, seconds, (temp_svcstatus->last_state_change == (time_t)0) ? "+" : "");
	state_duration[sizeof(state_duration) - 1] = '\x0';

	/* first, we mark and color it as maintenance if that is preferred */
	if (suppress_maintenance_downtime == TRUE && temp_svcstatus->scheduled_downtime_depth > 0) {
		strcpy(state_string, "维护");
		bg_class = "serviceDOWNTIME";

		/* otherwise we mark and color it with its appropriate state */
	} else if (temp_svcstatus->status == SERVICE_OK) {
		strcpy(state_string, "正常");
		bg_class = "serviceOK";
	} else if (temp_svcstatus->status == SERVICE_WARNING) {
		strcpy(state_string, "警报");
		bg_class = "serviceWARNING";
	} else if (temp_svcstatus->status == SERVICE_CRITICAL) {
		strcpy(state_string, "严重");
		bg_class = "serviceCRITICAL";
	} else {
		strcpy(state_string, "未知");
		bg_class = "serviceUNKNOWN";
	}

	duration_error = FALSE;
	if (temp_svcstatus->last_check > current_time)
		duration_error = TRUE;
	else
		ts_state_age = current_time - temp_svcstatus->last_update;
	get_time_breakdown((unsigned long)ts_state_age, &days, &hours, &minutes, &seconds);
	if (duration_error == TRUE)
		snprintf(status_age, sizeof(status_age) - 1, "???");
	else if (temp_svcstatus->last_check == (time_t)0)
		snprintf(status_age, sizeof(status_age) - 1, "无");
	else
		snprintf(status_age, sizeof(status_age) - 1, "%2d天%2d时%2d分%2d秒", days, hours, minutes, seconds);
	status_age[sizeof(status_age)-1] = '\x0';

	if (content_type == JSON_CONTENT) {
		printf("\"服务信息\": {\n");
		printf("\"主机名称\": \"%s\",\n", json_encode(host_name));
		printf("\"主机显示名称\": \"%s\",\n", (temp_host != NULL && temp_host->display_name != NULL) ? json_encode(temp_host->display_name) : json_encode(host_name));
		printf("\"服务描述\": \"%s\",\n", json_encode(service_desc));
		printf("\"服务显示描述\": \"%s\",\n", (temp_service->display_name != NULL) ? json_encode(temp_service->display_name) : json_encode(service_desc));
		if (temp_svcstatus->has_been_checked == FALSE)
			printf("\"完成检查\": false\n");
		else {
			printf("\"完成检查\": true,\n");
			printf("\"状态\": \"%s\",\n", state_string);
			printf("\"状态类型\": \"%s\",\n", (temp_svcstatus->state_type == HARD_STATE) ? "硬" : "软");
			if (duration_error == TRUE)
				printf("\"状态持续时间\": false,\n");
			else
				printf("\"状态持续时间\": \"%s\",\n", state_duration);
			printf("\"状态持续时间(秒)\": %lu,\n", (unsigned long)ts_state_duration);
			if (temp_svcstatus->long_plugin_output != NULL)
				printf("\"状态信息\": \"%s\\n%s\",\n", json_encode(temp_svcstatus->plugin_output), json_encode(temp_svcstatus->long_plugin_output));
			else if (temp_svcstatus->plugin_output != NULL)
				printf("\"状态信息\": \"%s\",\n", json_encode(temp_svcstatus->plugin_output));
			else
				printf("\"状态信息\": null,\n");
			if (temp_svcstatus->perf_data == NULL)
				printf("\"性能数据\": null,\n");
			else
				printf("\"性能数据\": \"%s\",\n", json_encode(temp_svcstatus->perf_data));
			printf("\"当前尝试\": %d,\n", temp_svcstatus->current_attempt);
			printf("\"最大尝试\": %d,\n", temp_svcstatus->max_attempts);

			if (temp_svcstatus->checks_enabled == TRUE)
				printf("\"检查类型\": \"主动\",\n");
			else if (temp_svcstatus->accept_passive_service_checks == TRUE)
				printf("\"检查类型\": \"被动\",\n");
			else
				printf("\"检查类型\": \"禁用\",\n");

			get_time_string(&temp_svcstatus->last_check, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			printf("\"最近检查时间\": \"%s\",\n", date_time);

			if (temp_svcstatus->checks_enabled == TRUE)
				printf("\"检查延迟\": %.3f,\n", temp_svcstatus->latency);
			else
				printf("\"检查延迟\": null,\n");
			printf("\"检查持续时间\": %.3f,\n", temp_svcstatus->execution_time);

			get_time_string(&temp_svcstatus->next_check, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			if (temp_svcstatus->checks_enabled && temp_svcstatus->next_check != (time_t)0 && temp_svcstatus->should_be_scheduled == TRUE)
				printf("\"安排下一次主动检查\": \"%s\",\n", date_time);
			else
				printf("\"安排下一次主动检查\": null,\n");

			get_time_string(&temp_svcstatus->last_state_change, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			if (temp_svcstatus->last_state_change == (time_t)0)
				printf("\"最近状态变化\": null,\n");
			else
				printf("\"最近状态变化\": \"%s\",\n", date_time);

			get_time_string(&temp_svcstatus->last_notification, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			if (temp_svcstatus->last_notification == (time_t)0)
				printf("\"最近通知\": null,\n");
			else
				printf("\"最近通知\": \"%s\",\n", date_time);
			printf("\"当前通知的成员\": %d,\n", temp_svcstatus->current_notification_number);
			if (temp_svcstatus->flap_detection_enabled == FALSE || enable_flap_detection == FALSE)
				printf("\"服务抖动\": null,\n");
			else
				printf("\"服务抖动\": %s,\n", (temp_svcstatus->is_flapping == TRUE) ? "true" : "false");
			printf("\"抖动状态变化率\": %3.2f,\n", temp_svcstatus->percent_state_change);
			printf("\"安排宕机中的服务\": %s,\n", (temp_svcstatus->scheduled_downtime_depth > 0) ? "true" : "false");
			printf("\"已确认的服务\": %s,\n", (temp_svcstatus->problem_has_been_acknowledged == TRUE) ? "true" : "false");

			get_time_string(&temp_svcstatus->last_update, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			printf("\"最近更新\": \"%s\",\n", date_time);

			printf("\"属性修改\": \"");
			print_modified_attributes(JSON_CONTENT, EXTINFO_CGI, temp_svcstatus->modified_attributes);
			printf("\",\n");

			printf("\"启用主动检查\": %s,\n", (temp_svcstatus->checks_enabled == TRUE) ? "true" : "false");
			printf("\"启用被动检查\": %s,\n", (temp_svcstatus->accept_passive_service_checks == TRUE) ? "true" : "false");
			printf("\"强迫服务\": %s,\n", (temp_svcstatus->obsess_over_service == TRUE) ? "true" : "false");
			printf("\"启用通知\": %s,\n", (temp_svcstatus->notifications_enabled == TRUE) ? "true" : "false");
			printf("\"启用事件处理\": %s,\n", (temp_svcstatus->event_handler_enabled == TRUE) ? "true" : "false");
			printf("\"启用抖动检测\": %s\n", (temp_svcstatus->flap_detection_enabled == TRUE) ? "true" : "false");
			if (is_authorized_for_read_only(&current_authdata) == FALSE || is_authorized_for_comments_read_only(&current_authdata) == TRUE) {

				/* display comments */
				printf(",\n");
				show_comments(SERVICE_COMMENT);

				/* display downtimes */
				printf(",\n");
				show_downtime(SERVICE_DOWNTIME);
			}
			printf(" }\n");
		}
	} else {
		printf("<TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=100%%>\n");
		printf("<TR>\n");

		printf("<TD ALIGN=CENTER VALIGN=TOP CLASS='stateInfoPanel'>\n");

		printf("<DIV CLASS='dataTitle'>服务状态信息</DIV>\n");

		if (temp_svcstatus->has_been_checked == FALSE)
			printf("<P><DIV ALIGN=CENTER>该服务未被检查，因此状态信息不可用.</DIV></P>\n");

		else {

			printf("<TABLE BORDER=0>\n");

			printf("<TR><TD>\n");

			printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0>\n");
			printf("<TR><TD class='stateInfoTable1'>\n");
			printf("<TABLE BORDER=0>\n");

			printf("<TR><TD CLASS='dataVar'>当前状态:</TD><TD CLASS='dataVal'><DIV CLASS='%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV>&nbsp;(为 %s)%s</TD></TR>\n", bg_class, state_string, state_duration, (temp_svcstatus->problem_has_been_acknowledged == TRUE) ? "&nbsp;&nbsp;(已确认)" : "");

			printf("<TR><TD CLASS='dataVar' VALIGN='top'>状态信息:</TD><TD CLASS='dataVal'>%s", (temp_svcstatus->plugin_output == NULL) ? "" : html_encode(temp_svcstatus->plugin_output, TRUE));
			if (enable_splunk_integration == TRUE) {
				printf("&nbsp;&nbsp;");
				dummy = asprintf(&buf, "%s %s %s", temp_service->host_name, temp_service->description, temp_svcstatus->plugin_output);
				buf[sizeof(buf) - 1] = '\x0';
				display_splunk_generic_url(buf, 1);
				free(buf);
			}
			if (temp_svcstatus->long_plugin_output != NULL)
				printf("<BR>%s", html_encode(temp_svcstatus->long_plugin_output, TRUE));
			printf("</TD></TR>\n");

			printf("<TR><TD CLASS='dataVar' VALIGN='top'>性能数据:</td><td CLASS='dataVal'>%s</td></tr>\n", (temp_svcstatus->perf_data == NULL) ? "" : html_encode(temp_svcstatus->perf_data, TRUE));

			printf("<TR><TD CLASS='dataVar'>当前尝试:</TD><TD CLASS='dataVal'>%d/%d", temp_svcstatus->current_attempt, temp_svcstatus->max_attempts);
			printf("&nbsp;&nbsp;(%s状态)</TD></TR>\n", (temp_svcstatus->state_type == HARD_STATE) ? "硬" : "软");

			get_time_string(&temp_svcstatus->last_check, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			printf("<TR><TD CLASS='dataVar'>最近检查时间:</TD><TD CLASS='dataVal'>%s</TD></TR>\n", date_time);

			if (temp_svcstatus->checks_enabled == TRUE)
				printf("<TR><TD CLASS='dataVar'>检查类型:</TD><TD CLASS='dataVal'><A HREF='%s?type=command&host=%s&service=%s&expand=%s'>ACTIVE</A></TD></TR>\n",
				       CONFIG_CGI, url_encode(host_name), url_encode(service_desc), url_encode(temp_service->service_check_command));
			else if (temp_svcstatus->accept_passive_service_checks == TRUE)
				printf("<TR><TD CLASS='dataVar'>检查类型:</TD><TD CLASS='dataVal'>被动</TD></TR>\n");
			else
				printf("<TR><TD CLASS='dataVar'>检查类型:</TD><TD CLASS='dataVal'>禁用</TD></TR>\n");

			printf("<TR><TD CLASS='dataVar' NOWRAP>检查延迟／持续时间:</TD><TD CLASS='dataVal'>");
			if (temp_svcstatus->checks_enabled == TRUE)
				printf("%.3f", temp_svcstatus->latency);
			else
				printf("无");
			printf("&nbsp;/&nbsp;%.3f 秒", temp_svcstatus->execution_time);
			printf("</TD></TR>\n");

			get_time_string(&temp_svcstatus->next_check, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			printf("<TR><TD CLASS='dataVar'>安排下一次检查:&nbsp;&nbsp;</TD><TD CLASS='dataVal'>%s</TD></TR>\n", (temp_svcstatus->checks_enabled && temp_svcstatus->next_check != (time_t)0 && temp_svcstatus->should_be_scheduled == TRUE) ? date_time : "无");

			get_time_string(&temp_svcstatus->last_state_change, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			printf("<TR><TD CLASS='dataVar'>最近状态变化:</TD><TD CLASS='dataVal'>%s</TD></TR>\n", (temp_svcstatus->last_state_change == (time_t)0) ? "无" : date_time);

			get_time_string(&temp_svcstatus->last_notification, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			printf("<TR><TD CLASS='dataVar'>最近通知:</TD><TD CLASS='dataVal'>%s&nbsp;(notification %d)</TD></TR>\n", (temp_svcstatus->last_notification == (time_t)0) ? "无" : date_time, temp_svcstatus->current_notification_number);

			printf("<TR><TD CLASS='dataVar'>该服务抖动?</TD><TD CLASS='dataVal'>");
			if (temp_svcstatus->flap_detection_enabled == FALSE || enable_flap_detection == FALSE)
				printf("无");
			else
				printf("<DIV CLASS='%sflapping'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV>&nbsp;(%3.2f%%状态变化)", (temp_svcstatus->is_flapping == TRUE) ? "" : "not", (temp_svcstatus->is_flapping == TRUE) ? "是" : "否", temp_svcstatus->percent_state_change);
			printf("</TD></TR>\n");

			printf("<TR><TD CLASS='dataVar'>安排宕机中?</TD><TD CLASS='dataVal'><DIV CLASS='downtime%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></TD></TR>\n", (temp_svcstatus->scheduled_downtime_depth > 0) ? "ACTIVE" : "INACTIVE", (temp_svcstatus->scheduled_downtime_depth > 0) ? "是" : "否");


			get_time_string(&temp_svcstatus->last_update, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			printf("<TR><TD CLASS='dataVar'>最近更新:</TD><TD CLASS='dataVal'>%s&nbsp;&nbsp;(%s以前)</TD></TR>\n", (temp_svcstatus->last_update == (time_t)0) ? "无" : date_time, status_age);

			printf("<TR><TD CLASS='dataVar'>属性修改:</td><td CLASS='dataVal'>");
			print_modified_attributes(HTML_CONTENT, EXTINFO_CGI, temp_svcstatus->modified_attributes);
			printf("</td></tr>\n");

			printf("<TR><TD CLASS='dataVar'>Executed Command:</TD><TD CLASS='dataVal'><A HREF='%s?type=command&host=%s&service=%s&expand=%s'>Command Expander</A></TD></TR>\n", CONFIG_CGI, url_encode(host_name), url_encode(service_desc), url_encode(temp_service->service_check_command));

			printf("</TABLE>\n");
			printf("</TD></TR>\n");
			printf("</TABLE>\n");

			printf("</TD></TR>\n");

			printf("<TR><TD>\n");

			printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0 align='left'>\n");
			printf("<TR><TD class='stateInfoTable2'>\n");
			printf("<TABLE BORDER=0>\n");

			if ((temp_service->service_check_command) && (*temp_service->service_check_command != '\0'))
				printf("<TR><TD CLASS='dataVar'><A HREF='%s?type=command&expand=%s'>主动检查:</A></TD><td CLASS='dataVal'><DIV CLASS='checks%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></TD></TR>\n", CONFIG_CGI, url_encode(temp_service->service_check_command), (temp_svcstatus->checks_enabled) ? "ENABLED" : "DISABLED", (temp_svcstatus->checks_enabled) ? "启用" : "禁用");
			else printf("<TR><TD CLASS='dataVar'>主动检查:</TD><td CLASS='dataVal'><DIV CLASS='checks%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></TD></TR>\n", (temp_svcstatus->checks_enabled) ? "ENABLED" : "DISABLED", (temp_svcstatus->checks_enabled) ? "启用" : "禁用");

			printf("<TR><TD CLASS='dataVar'>被动检查:</TD><td CLASS='dataVal'><DIV CLASS='checks%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></TD></TR>\n", (temp_svcstatus->accept_passive_service_checks == TRUE) ? "ENABLED" : "DISABLED", (temp_svcstatus->accept_passive_service_checks) ? "启用" : "禁用");

			printf("<TR><TD CLASS='dataVar'>强迫:</TD><td CLASS='dataVal'><DIV CLASS='checks%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></TD></TR>\n", (temp_svcstatus->obsess_over_service == TRUE) ? "ENABLED" : "DISABLED", (temp_svcstatus->obsess_over_service) ? "启用" : "禁用");

			printf("<TR><td CLASS='dataVar'>通知:</TD><td CLASS='dataVal'><DIV CLASS='notifications%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></TD></TR>\n", (temp_svcstatus->notifications_enabled) ? "ENABLED" : "DISABLED", (temp_svcstatus->notifications_enabled) ? "启用" : "禁用");

			if ((temp_service->event_handler) && (*temp_service->event_handler != '\0'))
				printf("<TR><TD CLASS='dataVar'><A HREF='%s?type=command&expand=%s'>事件处理:</A></td><td CLASS='dataVal'><DIV CLASS='eventhandlers%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></td></tr>\n", CONFIG_CGI, url_encode(temp_service->event_handler), (temp_svcstatus->event_handler_enabled) ? "ENABLED" : "DISABLED", (temp_svcstatus->event_handler_enabled) ? "启用" : "禁用");
			else printf("<TR><TD CLASS='dataVar'>事件处理:</td><td CLASS='dataVal'><DIV CLASS='eventhandlers%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></td></tr>\n", (temp_svcstatus->event_handler_enabled) ? "ENABLED" : "DISABLED", (temp_svcstatus->event_handler_enabled) ? "启用" : "禁用");

			printf("<TR><TD CLASS='dataVar'>抖动检测:</TD><td CLASS='dataVal'><DIV CLASS='flapdetection%s'>&nbsp;&nbsp;%s&nbsp;&nbsp;</DIV></TD></TR>\n", (temp_svcstatus->flap_detection_enabled == TRUE) ? "ENABLED" : "DISABLED", (temp_svcstatus->flap_detection_enabled == TRUE) ? "启用" : "禁用");


			printf("</TABLE>\n");
			printf("</TD></TR>\n");
			printf("</TABLE>\n");

			printf("</TD></TR>\n");

			printf("</TABLE>\n");
		}


		printf("</TD>\n");

		printf("<TD ALIGN=CENTER VALIGN=TOP>\n");
		printf("<TABLE BORDER='0' CELLPADDING=0 CELLSPACING=0><TR>\n");

		printf("<TD ALIGN=CENTER VALIGN=TOP CLASS='commandPanel'>\n");

		printf("<DIV CLASS='dataTitle'>服务命令</DIV>\n");

		printf("<TABLE BORDER='1' CELLSPACING=0 CELLPADDING=0>\n");
		printf("<TR><TD>\n");

		if (is_authorized_for_read_only(&current_authdata) == FALSE) {
			printf("<TABLE BORDER=0 CELLSPACING=0 CELLPADDING=0 CLASS='command'>\n");

			if (temp_svcstatus->checks_enabled) {

				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='禁用该服务的主动检查' TITLE='禁用该服务的主动检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_SVC_CHECK, url_encode(host_name));
				printf("&service=%s'>禁用该服务的主动检查</a></td></tr>\n", url_encode(service_desc));
			} else {
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='启用该服务的主动检查' TITLE='启用该服务的主动检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_SVC_CHECK, url_encode(host_name));
				printf("&service=%s'>启用该服务的主动检查</a></td></tr>\n", url_encode(service_desc));
			}
			printf("<tr CLASS='data'><td><img src='%s%s' border=0 ALT='重新安排下一次服务检查' TITLE='重新安排下一次服务检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s", url_images_path, DELAY_ICON, CMD_CGI, CMD_SCHEDULE_SVC_CHECK, url_encode(host_name));
			printf("&service=%s%s'>重新安排下一次服务检查</a></td></tr>\n", url_encode(service_desc), (temp_svcstatus->checks_enabled == TRUE) ? "&force_check" : "");

			if (temp_svcstatus->accept_passive_service_checks == TRUE) {
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='提交该服务的被动检查结果' TITLE='提交该服务的被动检查结果'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s", url_images_path, PASSIVE_ICON, CMD_CGI, CMD_PROCESS_SERVICE_CHECK_RESULT, url_encode(host_name));
				printf("&service=%s'>提交该服务的被动检查结果</a></td></tr>\n", url_encode(service_desc));

				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='停止接受该服务被动检查' TITLE='停止接受该服务被动检查'></td><td CLASS='command' NOWRAP><a href='%s?cmd_typ=%d&host=%s", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_PASSIVE_SVC_CHECKS, url_encode(host_name));
				printf("&service=%s'>停止接受该服务被动检查</a></td></tr>\n", url_encode(service_desc));
			} else {
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='开始接受该服务被动检查' TITLE='开始接受该服务被动检查'></td><td CLASS='command' NOWRAP><a href='%s?cmd_typ=%d&host=%s", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_PASSIVE_SVC_CHECKS, url_encode(host_name));
				printf("&service=%s'>开始接受该服务被动检查</a></td></tr>\n", url_encode(service_desc));
			}

			if (temp_svcstatus->obsess_over_service == TRUE) {
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='停止强迫该服务' TITLE='停止强迫该服务'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s", url_images_path, DISABLED_ICON, CMD_CGI, CMD_STOP_OBSESSING_OVER_SVC, url_encode(host_name));
				printf("&service=%s'>停止强迫该服务</a></td></tr>\n", url_encode(service_desc));
			} else {
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='开始强迫该服' TITLE='开始强迫该服'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s", url_images_path, ENABLED_ICON, CMD_CGI, CMD_START_OBSESSING_OVER_SVC, url_encode(host_name));
				printf("&service=%s'>开始强迫该服</a></td></tr>\n", url_encode(service_desc));
			}

			if ((temp_svcstatus->status == SERVICE_WARNING || temp_svcstatus->status == SERVICE_UNKNOWN || temp_svcstatus->status == SERVICE_CRITICAL) && temp_svcstatus->state_type == HARD_STATE) {
				if (temp_svcstatus->problem_has_been_acknowledged == FALSE) {
					printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='确认该服务故障' TITLE='确认该服务故障'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s", url_images_path, ACKNOWLEDGEMENT_ICON, CMD_CGI, CMD_ACKNOWLEDGE_SVC_PROBLEM, url_encode(host_name));
					printf("&service=%s'>确认该服务故障</a></td></tr>\n", url_encode(service_desc));
				} else {
					printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='移除故障确认' TITLE='移除故障确'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s", url_images_path, REMOVE_ACKNOWLEDGEMENT_ICON, CMD_CGI, CMD_REMOVE_SVC_ACKNOWLEDGEMENT, url_encode(host_name));
					printf("&service=%s'>移除故障确</a></td></tr>\n", url_encode(service_desc));
				}
			}
			if (temp_svcstatus->notifications_enabled == TRUE) {
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='禁用该服务通知' TITLE='禁用该服务通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_SVC_NOTIFICATIONS, url_encode(host_name));
				printf("&service=%s'>禁用该服务通知</a></td></tr>\n", url_encode(service_desc));
				if (temp_svcstatus->status != SERVICE_OK) {
					printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='延迟下一次服务通知' TITLE='延迟下一次服务通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s", url_images_path, DELAY_ICON, CMD_CGI, CMD_DELAY_SVC_NOTIFICATION, url_encode(host_name));
					printf("&service=%s'>延迟下一次服务通知</a></td></tr>\n", url_encode(service_desc));
				}
			} else {
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='启用该服务通知' TITLE='启用该服务通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_SVC_NOTIFICATIONS, url_encode(host_name));
				printf("&service=%s'>启用该服务通知</a></td></tr>\n", url_encode(service_desc));
			}

			printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='发送自定义服务通知' TITLE='发送自定义服务通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s", url_images_path, NOTIFICATION_ICON, CMD_CGI, CMD_SEND_CUSTOM_SVC_NOTIFICATION, url_encode(host_name));
			printf("&service=%s'>发送自定义服务通知</a></td></tr>\n", url_encode(service_desc));

			printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='安排该服务宕机' TITLE='安排该服务宕机'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s", url_images_path, DOWNTIME_ICON, CMD_CGI, CMD_SCHEDULE_SVC_DOWNTIME, url_encode(host_name));
			printf("&service=%s'>安排该服务宕机</a></td></tr>\n", url_encode(service_desc));

			/*
			printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='取消安排该服务宕机' TITLE='取消安排该服务宕机'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s",url_images_path,DOWNTIME_ICON,CMD_CGI,CMD_CANCEL_SVC_DOWNTIME,url_encode(host_name));
			printf("&service=%s'>取消安排该服务宕机</a></td></tr>\n",url_encode(service_desc));
			*/

			if (temp_svcstatus->event_handler_enabled == TRUE) {
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='禁用该服务事件处理' TITLE='禁用该服务事件处理'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_SVC_EVENT_HANDLER, url_encode(host_name));
				printf("&service=%s'>禁用该服务事件处理</a></td></tr>\n", url_encode(service_desc));
			} else {
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='启用该服务事件处理' TITLE='启用该服务事件处理'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_SVC_EVENT_HANDLER, url_encode(host_name));
				printf("&service=%s'>启用该服务事件处理</a></td></tr>\n", url_encode(service_desc));
			}

			if (temp_svcstatus->flap_detection_enabled == TRUE) {
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='禁用该服务抖动检测' TITLE='禁用该服务抖动检测'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_SVC_FLAP_DETECTION, url_encode(host_name));
				printf("&service=%s'>禁用该服务抖动检测</a></td></tr>\n", url_encode(service_desc));
			} else {
				printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='启用该服务抖动检测' TITLE='启用该服务抖动检测'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_SVC_FLAP_DETECTION, url_encode(host_name));
				printf("&service=%s'>启用该服务抖动检测</a></td></tr>\n", url_encode(service_desc));
			}

			printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='添加新服务注释' TITLE='添加新服务注释'></td><td CLASS='command'><a href='%s?cmd_typ=%d&host=%s&", url_images_path, COMMENT_ICON, CMD_CGI, CMD_ADD_SVC_COMMENT, (display_type == DISPLAY_COMMENTS) ? "" : url_encode(host_name));
			printf("service=%s'>", (display_type == DISPLAY_COMMENTS) ? "" : url_encode(service_desc));
			printf("添加新服务注释</a></td>");

			/* allow modified attributes to be reset */
			printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='重置属性修改' TITLE='重置属性修改'></td><td CLASS='command'><a href='%s?cmd_typ=%d&attr=%d&host=%s&", url_images_path, DISABLED_ICON, CMD_CGI, CMD_CHANGE_SVC_MODATTR, MODATTR_NONE, (display_type == DISPLAY_COMMENTS) ? "" : url_encode(host_name));
			printf("service=%s'>", (display_type == DISPLAY_COMMENTS) ? "" : url_encode(service_desc));
			printf("重置属性修改</a></td>");


			printf("</table>\n");
		} else {
			print_generic_error_message("您的帐户没有权限执行命令.", NULL, 0);
		}

		printf("</td></tr>\n");
		printf("</table>\n");

		printf("</TD>\n");

		printf("</TR></TABLE></TD>\n");
		printf("</TR>\n");

		printf("<TR><TD COLSPAN=2><BR></TD></TR>\n");

		printf("<TR>\n");
		printf("<TD COLSPAN=2 VALIGN=TOP CLASS='commentPanel'>\n");

		if (is_authorized_for_read_only(&current_authdata) == FALSE || is_authorized_for_comments_read_only(&current_authdata) == TRUE) {
			/* display comments */
			show_comments(SERVICE_COMMENT);
			printf("<BR>");
			/* display downtimes */
			show_downtime(SERVICE_DOWNTIME);
		}
		printf("</TD>\n");
		printf("</TR>\n");

		printf("</TABLE>\n");
	}

	return;
}

void show_hostgroup_info(void) {
	hostgroup *temp_hostgroup;

	/* get hostgroup info */
	temp_hostgroup = find_hostgroup(hostgroup_name);

	/* make sure the user has rights to view hostgroup information */
	if (is_authorized_for_hostgroup(temp_hostgroup, &current_authdata) == FALSE) {
		print_generic_error_message("很显然您的没有权限查看该主机组信息...","如果您认为这是一个错误, 请检查访问CGI的HTTP服务器身份验证要求,并检查您的CGI配置文件的授权选项.", 0);
		return;
	}

	/* make sure hostgroup information exists */
	if (temp_hostgroup == NULL) {
		print_generic_error_message("错误: 主机组不存在!", NULL, 0);
		return;
	}

	printf("<DIV CLASS='dataTitle'>主机组命令</DIV>\n");

	if (is_authorized_for_read_only(&current_authdata) == FALSE) {

		printf("<TABLE border=0 CELLSPACING=0 CELLPADDING=0 CLASS='command' align='center'>\n");

		printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT=''安排该主机组中所有主机宕机' TITLE=''安排该主机组中所有主机宕机'></td><td CLASS='command'><a href='%s?cmd_typ=%d&hostgroup=%s'>'安排该主机组中所有主机宕机</a></td></tr>\n", url_images_path, DOWNTIME_ICON, CMD_CGI, CMD_SCHEDULE_HOSTGROUP_HOST_DOWNTIME, url_encode(hostgroup_name));

		printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='安排该主机组中所有服务宕机' TITLE='安排该主机组中所有服务宕机'></td><td CLASS='command'><a href='%s?cmd_typ=%d&hostgroup=%s'>安排该主机组中所有服务宕机</a></td></tr>\n", url_images_path, DOWNTIME_ICON, CMD_CGI, CMD_SCHEDULE_HOSTGROUP_SVC_DOWNTIME, url_encode(hostgroup_name));

		printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='启用该主机组中所有主机通知' TITLE='启用该主机组中所有主机通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&hostgroup=%s'>启用该主机组中所有主机通知</a></td></tr>\n", url_images_path, NOTIFICATION_ICON, CMD_CGI, CMD_ENABLE_HOSTGROUP_HOST_NOTIFICATIONS, url_encode(hostgroup_name));

		printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='禁用该主机组中所有主机通知' TITLE='禁用该主机组中所有主机通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&hostgroup=%s'>禁用该主机组中所有主机通知</a></td></tr>\n", url_images_path, NOTIFICATIONS_DISABLED_ICON, CMD_CGI, CMD_DISABLE_HOSTGROUP_HOST_NOTIFICATIONS, url_encode(hostgroup_name));

		printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='启用该主机组中所有服务通知' TITLE='启用该主机组中所有服务通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&hostgroup=%s'>启用该主机组中所有服务通知</a></td></tr>\n", url_images_path, NOTIFICATION_ICON, CMD_CGI, CMD_ENABLE_HOSTGROUP_SVC_NOTIFICATIONS, url_encode(hostgroup_name));

		printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='禁用该主机组中所有服务通知' TITLE='禁用该主机组中所有服务通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&hostgroup=%s'>禁用该主机组中所有服务通知</a></td></tr>\n", url_images_path, NOTIFICATIONS_DISABLED_ICON, CMD_CGI, CMD_DISABLE_HOSTGROUP_SVC_NOTIFICATIONS, url_encode(hostgroup_name));

		printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='启用该主机组中所有服务主动检查' TITLE='启用该主机组中所有服务主动检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d&hostgroup=%s'>启用该主机组中所有服务主动检查</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_HOSTGROUP_SVC_CHECKS, url_encode(hostgroup_name));

		printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='禁用该主机组中所有服务主动检查' TITLE='禁用该主机组中所有服务主动检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d&hostgroup=%s'>禁用该主机组中所有服务主动检查</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_HOSTGROUP_SVC_CHECKS, url_encode(hostgroup_name));

		printf("</table>\n");

	} else {
		print_generic_error_message("您的帐户没有权限执行命令.", NULL, 0);
	}

	return;
}

void show_servicegroup_info() {
	servicegroup *temp_servicegroup;

	/* get servicegroup info */
	temp_servicegroup = find_servicegroup(servicegroup_name);

	/* make sure the user has rights to view servicegroup information */
	if (is_authorized_for_servicegroup(temp_servicegroup, &current_authdata) == FALSE) {
		print_generic_error_message("很显然您无权查看该服务组信息...","如果您认为这是一个错误, 请检查访问CGI的HTTP服务器身份验证要求,并检查您的CGI配置文件的授权选项.", 0);
		return;
	}

	/* make sure servicegroup information exists */
	if (temp_servicegroup == NULL) {
		print_generic_error_message("错误: 服务不存在!", NULL, 0);
		return;
	}

	printf("<DIV CLASS='dataTitle'>服务组命令</DIV>\n");

	if (is_authorized_for_read_only(&current_authdata) == FALSE) {

		printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0 CLASS='command' align='center'>\n");

		printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='安排该服务组所有主机宕机' TITLE='安排该服务组所有主机宕机'></td><td CLASS='command'><a href='%s?cmd_typ=%d&servicegroup=%s'>安排该服务组所有主机宕机</a></td></tr>\n", url_images_path, DOWNTIME_ICON, CMD_CGI, CMD_SCHEDULE_SERVICEGROUP_HOST_DOWNTIME, url_encode(servicegroup_name));

		printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='安排该服务组所有服务宕机' TITLE='安排该服务组所有服务宕机'></td><td CLASS='command'><a href='%s?cmd_typ=%d&servicegroup=%s'>安排该服务组所有服务宕机</a></td></tr>\n", url_images_path, DOWNTIME_ICON, CMD_CGI, CMD_SCHEDULE_SERVICEGROUP_SVC_DOWNTIME, url_encode(servicegroup_name));

		printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='启用该服务组所有主机通知' TITLE='启用该服务组所有主机通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&servicegroup=%s'>启用该服务组所有主机通知</a></td></tr>\n", url_images_path, NOTIFICATION_ICON, CMD_CGI, CMD_ENABLE_SERVICEGROUP_HOST_NOTIFICATIONS, url_encode(servicegroup_name));

		printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='禁用该服务组所有主机通知' TITLE='禁用该服务组所有主机通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&servicegroup=%s'>禁用该服务组所有主机通知</a></td></tr>\n", url_images_path, NOTIFICATIONS_DISABLED_ICON, CMD_CGI, CMD_DISABLE_SERVICEGROUP_HOST_NOTIFICATIONS, url_encode(servicegroup_name));

		printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='启用该服务组所有服务通知' TITLE='启用该服务组所有服务通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&servicegroup=%s'>启用该服务组所有服务通知</a></td></tr>\n", url_images_path, NOTIFICATION_ICON, CMD_CGI, CMD_ENABLE_SERVICEGROUP_SVC_NOTIFICATIONS, url_encode(servicegroup_name));

		printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='禁用该服务组所有服务通知' TITLE='禁用该服务组所有服务通知'></td><td CLASS='command'><a href='%s?cmd_typ=%d&servicegroup=%s'>禁用该服务组所有服务通知</a></td></tr>\n", url_images_path, NOTIFICATIONS_DISABLED_ICON, CMD_CGI, CMD_DISABLE_SERVICEGROUP_SVC_NOTIFICATIONS, url_encode(servicegroup_name));

		printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='启用该服务组所有服务主动检查' TITLE='启用该服务组所有服务主动检查'></td><td CLASS='command'><a href='%s?cmd_typ=%d&servicegroup=%s'>启用该服务组所有服务主动检查</a></td></tr>\n", url_images_path, ENABLED_ICON, CMD_CGI, CMD_ENABLE_SERVICEGROUP_SVC_CHECKS, url_encode(servicegroup_name));

		printf("<tr CLASS='command'><td><img src='%s%s' border=0 ALT='禁用该服务组所有服务主动检' TITLE='禁用该服务组所有服务主动检'></td><td CLASS='command'><a href='%s?cmd_typ=%d&servicegroup=%s'>禁用该服务组所有服务主动检</a></td></tr>\n", url_images_path, DISABLED_ICON, CMD_CGI, CMD_DISABLE_SERVICEGROUP_SVC_CHECKS, url_encode(servicegroup_name));

		printf("</table>\n");

	} else {
		print_generic_error_message("您的帐户没有权限执行命令.", NULL, 0);
	}

	return;
}

void show_performance_data(void) {
	service *temp_service = NULL;
	servicestatus *temp_servicestatus = NULL;
	host *temp_host = NULL;
	hoststatus *temp_hoststatus = NULL;
	int total_active_service_checks = 0;
	int total_passive_service_checks = 0;
	double min_service_execution_time = 0.0;
	double max_service_execution_time = 0.0;
	double total_service_execution_time = 0.0;
	int have_min_service_execution_time = FALSE;
	int have_max_service_execution_time = FALSE;
	double min_service_latency = 0.0;
	double max_service_latency = 0.0;
	double long total_service_latency = 0.0;
	int have_min_service_latency = FALSE;
	int have_max_service_latency = FALSE;
	double min_host_latency = 0.0;
	double max_host_latency = 0.0;
	double total_host_latency = 0.0;
	int have_min_host_latency = FALSE;
	int have_max_host_latency = FALSE;
	double min_service_percent_change_a = 0.0;
	double max_service_percent_change_a = 0.0;
	double total_service_percent_change_a = 0.0;
	int have_min_service_percent_change_a = FALSE;
	int have_max_service_percent_change_a = FALSE;
	double min_service_percent_change_b = 0.0;
	double max_service_percent_change_b = 0.0;
	double total_service_percent_change_b = 0.0;
	int have_min_service_percent_change_b = FALSE;
	int have_max_service_percent_change_b = FALSE;
	int active_service_checks_1min = 0;
	int active_service_checks_5min = 0;
	int active_service_checks_15min = 0;
	int active_service_checks_1hour = 0;
	int active_service_checks_start = 0;
	int active_service_checks_ever = 0;
	int passive_service_checks_1min = 0;
	int passive_service_checks_5min = 0;
	int passive_service_checks_15min = 0;
	int passive_service_checks_1hour = 0;
	int passive_service_checks_start = 0;
	int passive_service_checks_ever = 0;
	int total_active_host_checks = 0;
	int total_passive_host_checks = 0;
	double min_host_execution_time = 0.0;
	double max_host_execution_time = 0.0;
	double total_host_execution_time = 0.0;
	int have_min_host_execution_time = FALSE;
	int have_max_host_execution_time = FALSE;
	double min_host_percent_change_a = 0.0;
	double max_host_percent_change_a = 0.0;
	double total_host_percent_change_a = 0.0;
	int have_min_host_percent_change_a = FALSE;
	int have_max_host_percent_change_a = FALSE;
	double min_host_percent_change_b = 0.0;
	double max_host_percent_change_b = 0.0;
	double total_host_percent_change_b = 0.0;
	int have_min_host_percent_change_b = FALSE;
	int have_max_host_percent_change_b = FALSE;
	int active_host_checks_1min = 0;
	int active_host_checks_5min = 0;
	int active_host_checks_15min = 0;
	int active_host_checks_1hour = 0;
	int active_host_checks_start = 0;
	int active_host_checks_ever = 0;
	int passive_host_checks_1min = 0;
	int passive_host_checks_5min = 0;
	int passive_host_checks_15min = 0;
	int passive_host_checks_1hour = 0;
	int passive_host_checks_start = 0;
	int passive_host_checks_ever = 0;
	time_t current_time;
	/* make sure gcc3 won't hit here */
#ifndef GCCTOOOLD
	profile_object *t, *p = profiled_data;
	int count = 0;
	double elapsed = 0.0, total_time = 0.0;
	char *name = NULL;
#endif

	time(&current_time);

	/* check all services */
	for (temp_servicestatus = servicestatus_list; temp_servicestatus != NULL; temp_servicestatus = temp_servicestatus->next) {

		/* find the service */
		temp_service = find_service(temp_servicestatus->host_name, temp_servicestatus->description);

		/* make sure the user has rights to view service information */
		if (is_authorized_for_service(temp_service, &current_authdata) == FALSE)
			continue;

		/* is this an active or passive check? */
		if (temp_servicestatus->checks_enabled == TRUE) {

			total_active_service_checks++;

			total_service_execution_time += temp_servicestatus->execution_time;
			if (have_min_service_execution_time == FALSE || temp_servicestatus->execution_time < min_service_execution_time) {
				have_min_service_execution_time = TRUE;
				min_service_execution_time = temp_servicestatus->execution_time;
			}
			if (have_max_service_execution_time == FALSE || temp_servicestatus->execution_time > max_service_execution_time) {
				have_max_service_execution_time = TRUE;
				max_service_execution_time = temp_servicestatus->execution_time;
			}

			total_service_percent_change_a += temp_servicestatus->percent_state_change;
			if (have_min_service_percent_change_a == FALSE || temp_servicestatus->percent_state_change < min_service_percent_change_a) {
				have_min_service_percent_change_a = TRUE;
				min_service_percent_change_a = temp_servicestatus->percent_state_change;
			}
			if (have_max_service_percent_change_a == FALSE || temp_servicestatus->percent_state_change > max_service_percent_change_a) {
				have_max_service_percent_change_a = TRUE;
				max_service_percent_change_a = temp_servicestatus->percent_state_change;
			}

			total_service_latency += temp_servicestatus->latency;
			if (have_min_service_latency == FALSE || temp_servicestatus->latency < min_service_latency) {
				have_min_service_latency = TRUE;
				min_service_latency = temp_servicestatus->latency;
			}
			if (have_max_service_latency == FALSE || temp_servicestatus->latency > max_service_latency) {
				have_max_service_latency = TRUE;
				max_service_latency = temp_servicestatus->latency;
			}

			if (temp_servicestatus->last_check >= (current_time - 60))
				active_service_checks_1min++;
			if (temp_servicestatus->last_check >= (current_time - 300))
				active_service_checks_5min++;
			if (temp_servicestatus->last_check >= (current_time - 900))
				active_service_checks_15min++;
			if (temp_servicestatus->last_check >= (current_time - 3600))
				active_service_checks_1hour++;
			if (temp_servicestatus->last_check >= program_start)
				active_service_checks_start++;
			if (temp_servicestatus->last_check != (time_t)0)
				active_service_checks_ever++;

		} else if (temp_servicestatus->accept_passive_service_checks == TRUE) {
			total_passive_service_checks++;

			total_service_percent_change_b += temp_servicestatus->percent_state_change;
			if (have_min_service_percent_change_b == FALSE || temp_servicestatus->percent_state_change < min_service_percent_change_b) {
				have_min_service_percent_change_b = TRUE;
				min_service_percent_change_b = temp_servicestatus->percent_state_change;
			}
			if (have_max_service_percent_change_b == FALSE || temp_servicestatus->percent_state_change > max_service_percent_change_b) {
				have_max_service_percent_change_b = TRUE;
				max_service_percent_change_b = temp_servicestatus->percent_state_change;
			}

			if (temp_servicestatus->last_check >= (current_time - 60))
				passive_service_checks_1min++;
			if (temp_servicestatus->last_check >= (current_time - 300))
				passive_service_checks_5min++;
			if (temp_servicestatus->last_check >= (current_time - 900))
				passive_service_checks_15min++;
			if (temp_servicestatus->last_check >= (current_time - 3600))
				passive_service_checks_1hour++;
			if (temp_servicestatus->last_check >= program_start)
				passive_service_checks_start++;
			if (temp_servicestatus->last_check != (time_t)0)
				passive_service_checks_ever++;
		}
	}

	/* check all hosts */
	for (temp_hoststatus = hoststatus_list; temp_hoststatus != NULL; temp_hoststatus = temp_hoststatus->next) {

		/* find the host */
		temp_host = find_host(temp_hoststatus->host_name);

		/* make sure the user has rights to view host information */
		if (is_authorized_for_host(temp_host, &current_authdata) == FALSE)
			continue;

		/* is this an active or passive check? */
		if (temp_hoststatus->check_type == HOST_CHECK_ACTIVE) {

			total_active_host_checks++;

			total_host_execution_time += temp_hoststatus->execution_time;
			if (have_min_host_execution_time == FALSE || temp_hoststatus->execution_time < min_host_execution_time) {
				have_min_host_execution_time = TRUE;
				min_host_execution_time = temp_hoststatus->execution_time;
			}
			if (have_max_host_execution_time == FALSE || temp_hoststatus->execution_time > max_host_execution_time) {
				have_max_host_execution_time = TRUE;
				max_host_execution_time = temp_hoststatus->execution_time;
			}

			total_host_percent_change_a += temp_hoststatus->percent_state_change;
			if (have_min_host_percent_change_a == FALSE || temp_hoststatus->percent_state_change < min_host_percent_change_a) {
				have_min_host_percent_change_a = TRUE;
				min_host_percent_change_a = temp_hoststatus->percent_state_change;
			}
			if (have_max_host_percent_change_a == FALSE || temp_hoststatus->percent_state_change > max_host_percent_change_a) {
				have_max_host_percent_change_a = TRUE;
				max_host_percent_change_a = temp_hoststatus->percent_state_change;
			}

			total_host_latency += temp_hoststatus->latency;
			if (have_min_host_latency == FALSE || temp_hoststatus->latency < min_host_latency) {
				have_min_host_latency = TRUE;
				min_host_latency = temp_hoststatus->latency;
			}
			if (have_max_host_latency == FALSE || temp_hoststatus->latency > max_host_latency) {
				have_max_host_latency = TRUE;
				max_host_latency = temp_hoststatus->latency;
			}

			if (temp_hoststatus->last_check >= (current_time - 60))
				active_host_checks_1min++;
			if (temp_hoststatus->last_check >= (current_time - 300))
				active_host_checks_5min++;
			if (temp_hoststatus->last_check >= (current_time - 900))
				active_host_checks_15min++;
			if (temp_hoststatus->last_check >= (current_time - 3600))
				active_host_checks_1hour++;
			if (temp_hoststatus->last_check >= program_start)
				active_host_checks_start++;
			if (temp_hoststatus->last_check != (time_t)0)
				active_host_checks_ever++;
		}

		else {
			total_passive_host_checks++;

			total_host_percent_change_b += temp_hoststatus->percent_state_change;
			if (have_min_host_percent_change_b == FALSE || temp_hoststatus->percent_state_change < min_host_percent_change_b) {
				have_min_host_percent_change_b = TRUE;
				min_host_percent_change_b = temp_hoststatus->percent_state_change;
			}
			if (have_max_host_percent_change_b == FALSE || temp_hoststatus->percent_state_change > max_host_percent_change_b) {
				have_max_host_percent_change_b = TRUE;
				max_host_percent_change_b = temp_hoststatus->percent_state_change;
			}

			if (temp_hoststatus->last_check >= (current_time - 60))
				passive_host_checks_1min++;
			if (temp_hoststatus->last_check >= (current_time - 300))
				passive_host_checks_5min++;
			if (temp_hoststatus->last_check >= (current_time - 900))
				passive_host_checks_15min++;
			if (temp_hoststatus->last_check >= (current_time - 3600))
				passive_host_checks_1hour++;
			if (temp_hoststatus->last_check >= program_start)
				passive_host_checks_start++;
			if (temp_hoststatus->last_check != (time_t)0)
				passive_host_checks_ever++;
		}
	}


	printf("<div align=center>\n");


	printf("<DIV CLASS='dataTitle'>程序设定的性能信息</DIV>\n");

	printf("<table border='0' cellpadding='10'>\n");


	/***** ACTIVE SERVICE CHECKS *****/

	printf("<tr>\n");
	printf("<td valign=middle><div class='perfTypeTitle'>主动检查服务:</div></td>\n");
	printf("<td valign=top>\n");

	/* fake this so we don't divide by zero for just showing the table */
	if (total_active_service_checks == 0)
		total_active_service_checks = 1;

	printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0>\n");
	printf("<TR><TD class='stateInfoTable1'>\n");
	printf("<TABLE BORDER=0>\n");

	printf("<tr class='data'><th class='data'>时间框</th><th class='data'>检查服务</th></tr>\n");
	printf("<tr><td class='dataVar'>&lt;= 1 分钟:</td><td class='dataVal'>%d (%.1f%%)</td></tr>", active_service_checks_1min, (double)(((double)active_service_checks_1min * 100.0) / (double)total_active_service_checks));
	printf("<tr><td class='dataVar'>&lt;= 5 分钟:</td><td class='dataVal'>%d (%.1f%%)</td></tr>", active_service_checks_5min, (double)(((double)active_service_checks_5min * 100.0) / (double)total_active_service_checks));
	printf("<tr><td class='dataVar'>&lt;= 15 分钟:</td><td class='dataVal'>%d (%.1f%%)</td></tr>", active_service_checks_15min, (double)(((double)active_service_checks_15min * 100.0) / (double)total_active_service_checks));
	printf("<tr><td class='dataVar'>&lt;= 1 小时:</td><td class='dataVal'>%d (%.1f%%)</td></tr>", active_service_checks_1hour, (double)(((double)active_service_checks_1hour * 100.0) / (double)total_active_service_checks));
	printf("<tr><td class='dataVar'>自程序启动:&nbsp;&nbsp;</td><td class='dataVal'>%d (%.1f%%)</td>", active_service_checks_start, (double)(((double)active_service_checks_start * 100.0) / (double)total_active_service_checks));

	printf("</TABLE>\n");
	printf("</TD></TR>\n");
	printf("</TABLE>\n");

	printf("</td><td valign=top>\n");

	printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0>\n");
	printf("<TR><TD class='stateInfoTable2'>\n");
	printf("<TABLE BORDER=0>\n");

	printf("<tr class='data'><th class='data'>度量</th><th class='data'>最小.</th><th class='data'>最大.</th><th class='data'>平均</th></tr>\n");

	printf("<tr><td class='dataVar'>检查执行时间:&nbsp;&nbsp;</td><td class='dataVal'>%.2f 秒</td><td class='dataVal'>%.2f 秒</td><td class='dataVal'>%.3f 秒</td></tr>\n", min_service_execution_time, max_service_execution_time, (double)((double)total_service_execution_time / (double)total_active_service_checks));

	printf("<tr><td class='dataVar'>检查延迟:</td><td class='dataVal'>%.2f 秒</td><td class='dataVal'>%.2f 秒</td><td class='dataVal'>%.3f 秒</td></tr>\n", min_service_latency, max_service_latency, (double)((double)total_service_latency / (double)total_active_service_checks));

	printf("<tr><td class='dataVar'>状态变化率:</td><td class='dataVal'>%.2f%%</td><td class='dataVal'>%.2f%%</td><td class='dataVal'>%.2f%%</td></tr>\n", min_service_percent_change_a, max_service_percent_change_a, (double)((double)total_service_percent_change_a / (double)total_active_service_checks));

	printf("</TABLE>\n");
	printf("</TD></TR>\n");
	printf("</TABLE>\n");


	printf("</td>\n");
	printf("</tr>\n");


	/***** PASSIVE SERVICE CHECKS *****/

	printf("<tr>\n");
	printf("<td valign=middle><div class='perfTypeTitle'>被动检查服务:</div></td>\n");
	printf("<td valign=top>\n");


	/* fake this so we don't divide by zero for just showing the table */
	if (total_passive_service_checks == 0)
		total_passive_service_checks = 1;

	printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0>\n");
	printf("<TR><TD class='stateInfoTable1'>\n");
	printf("<TABLE BORDER=0>\n");

	printf("<tr class='data'><th class='data'>时间框</th><th class='data'>检查服务</th></tr>\n");
	printf("<tr><td class='dataVar'>&lt;= 1 分钟:</td><td class='dataVal'>%d (%.1f%%)</td></tr>", passive_service_checks_1min, (double)(((double)passive_service_checks_1min * 100.0) / (double)total_passive_service_checks));
	printf("<tr><td class='dataVar'>&lt;= 5 分钟:</td><td class='dataVal'>%d (%.1f%%)</td></tr>", passive_service_checks_5min, (double)(((double)passive_service_checks_5min * 100.0) / (double)total_passive_service_checks));
	printf("<tr><td class='dataVar'>&lt;= 15 分钟:</td><td class='dataVal'>%d (%.1f%%)</td></tr>", passive_service_checks_15min, (double)(((double)passive_service_checks_15min * 100.0) / (double)total_passive_service_checks));
	printf("<tr><td class='dataVar'>&lt;= 1 小时:</td><td class='dataVal'>%d (%.1f%%)</td></tr>", passive_service_checks_1hour, (double)(((double)passive_service_checks_1hour * 100.0) / (double)total_passive_service_checks));
	printf("<tr><td class='dataVar'>自程序启动:&nbsp;&nbsp;</td><td class='dataVal'>%d (%.1f%%)</td></tr>", passive_service_checks_start, (double)(((double)passive_service_checks_start * 100.0) / (double)total_passive_service_checks));

	printf("</TABLE>\n");
	printf("</TD></TR>\n");
	printf("</TABLE>\n");

	printf("</td><td valign=top>\n");

	printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0>\n");
	printf("<TR><TD class='stateInfoTable2'>\n");
	printf("<TABLE BORDER=0>\n");

	printf("<tr class='data'><th class='data'>度量</th><th class='data'>最小.</th><th class='data'>最大.</th><th class='data'>平均</th></tr>\n");
	printf("<tr><td class='dataVar'>状态变化率:&nbsp;&nbsp;</td><td class='dataVal'>%.2f%%</td><td class='dataVal'>%.2f%%</td><td class='dataVal'>%.2f%%</td></tr>\n", min_service_percent_change_b, max_service_percent_change_b, (double)((double)total_service_percent_change_b / (double)total_passive_service_checks));

	printf("</TABLE>\n");
	printf("</TD></TR>\n");
	printf("</TABLE>\n");

	printf("</td>\n");
	printf("</tr>\n");


	/***** ACTIVE HOST CHECKS *****/

	printf("<tr>\n");
	printf("<td valign=middle><div class='perfTypeTitle'>主动检查主机:</div></td>\n");
	printf("<td valign=top>\n");

	/* fake this so we don't divide by zero for just showing the table */
	if (total_active_host_checks == 0)
		total_active_host_checks = 1;

	printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0>\n");
	printf("<TR><TD class='stateInfoTable1'>\n");
	printf("<TABLE BORDER=0>\n");

	printf("<tr class='data'><th class='data'>时间框</th><th class='data'>检查主机</th></tr>\n");
	printf("<tr><td class='dataVar'>&lt;= 1 分钟:</td><td class='dataVal'>%d (%.1f%%)</td></tr>", active_host_checks_1min, (double)(((double)active_host_checks_1min * 100.0) / (double)total_active_host_checks));
	printf("<tr><td class='dataVar'>&lt;= 5 分钟:</td><td class='dataVal'>%d (%.1f%%)</td></tr>", active_host_checks_5min, (double)(((double)active_host_checks_5min * 100.0) / (double)total_active_host_checks));
	printf("<tr><td class='dataVar'>&lt;= 15 分钟:</td><td class='dataVal'>%d (%.1f%%)</td></tr>", active_host_checks_15min, (double)(((double)active_host_checks_15min * 100.0) / (double)total_active_host_checks));
	printf("<tr><td class='dataVar'>&lt;= 1 小时:</td><td class='dataVal'>%d (%.1f%%)</td></tr>", active_host_checks_1hour, (double)(((double)active_host_checks_1hour * 100.0) / (double)total_active_host_checks));
	printf("<tr><td class='dataVar'>自程序启动:&nbsp;&nbsp;</td><td class='dataVal'>%d (%.1f%%)</td>", active_host_checks_start, (double)(((double)active_host_checks_start * 100.0) / (double)total_active_host_checks));

	printf("</TABLE>\n");
	printf("</TD></TR>\n");
	printf("</TABLE>\n");

	printf("</td><td valign=top>\n");

	printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0>\n");
	printf("<TR><TD class='stateInfoTable2'>\n");
	printf("<TABLE BORDER=0>\n");

	printf("<tr class='data'><th class='data'>度量</th><th class='data'>最小.</th><th class='data'>最大.</th><th class='data'>平均</th></tr>\n");

	printf("<tr><td class='dataVar'>检查执行时间:&nbsp;&nbsp;</td><td class='dataVal'>%.2f 秒</td><td class='dataVal'>%.2f 秒</td><td class='dataVal'>%.3f 秒</td></tr>\n", min_host_execution_time, max_host_execution_time, (double)((double)total_host_execution_time / (double)total_active_host_checks));

	printf("<tr><td class='dataVar'>检查延迟:</td><td class='dataVal'>%.2f 秒</td><td class='dataVal'>%.2f 秒</td><td class='dataVal'>%.3f 秒</td></tr>\n", min_host_latency, max_host_latency, (double)((double)total_host_latency / (double)total_active_host_checks));

	printf("<tr><td class='dataVar'>状态变化率:</td><td class='dataVal'>%.2f%%</td><td class='dataVal'>%.2f%%</td><td class='dataVal'>%.2f%%</td></tr>\n", min_host_percent_change_a, max_host_percent_change_a, (double)((double)total_host_percent_change_a / (double)total_active_host_checks));

	printf("</TABLE>\n");
	printf("</TD></TR>\n");
	printf("</TABLE>\n");


	printf("</td>\n");
	printf("</tr>\n");


	/***** PASSIVE HOST CHECKS *****/

	printf("<tr>\n");
	printf("<td valign=middle><div class='perfTypeTitle'>被动检查主机:</div></td>\n");
	printf("<td valign=top>\n");


	/* fake this so we don't divide by zero for just showing the table */
	if (total_passive_host_checks == 0)
		total_passive_host_checks = 1;

	printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0>\n");
	printf("<TR><TD class='stateInfoTable1'>\n");
	printf("<TABLE BORDER=0>\n");

	printf("<tr class='data'><th class='data'>时间框</th><th class='data'>检查主机</th></tr>\n");
	printf("<tr><td class='dataVar'>&lt;= 1 分:</td><td class='dataVal'>%d (%.1f%%)</td></tr>", passive_host_checks_1min, (double)(((double)passive_host_checks_1min * 100.0) / (double)total_passive_host_checks));
	printf("<tr><td class='dataVar'>&lt;= 5 分:</td><td class='dataVal'>%d (%.1f%%)</td></tr>", passive_host_checks_5min, (double)(((double)passive_host_checks_5min * 100.0) / (double)total_passive_host_checks));
	printf("<tr><td class='dataVar'>&lt;= 15 分:</td><td class='dataVal'>%d (%.1f%%)</td></tr>", passive_host_checks_15min, (double)(((double)passive_host_checks_15min * 100.0) / (double)total_passive_host_checks));
	printf("<tr><td class='dataVar'>&lt;= 1 小时:</td><td class='dataVal'>%d (%.1f%%)</td></tr>", passive_host_checks_1hour, (double)(((double)passive_host_checks_1hour * 100.0) / (double)total_passive_host_checks));
	printf("<tr><td class='dataVar'>自程序启动:&nbsp;&nbsp;</td><td class='dataVal'>%d (%.1f%%)</td></tr>", passive_host_checks_start, (double)(((double)passive_host_checks_start * 100.0) / (double)total_passive_host_checks));

	printf("</TABLE>\n");
	printf("</TD></TR>\n");
	printf("</TABLE>\n");

	printf("</td><td valign=top>\n");

	printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0>\n");
	printf("<TR><TD class='stateInfoTable2'>\n");
	printf("<TABLE BORDER=0>\n");

	printf("<tr class='data'><th class='data'>度量</th><th class='data'>最小.</th><th class='data'>最大.</th><th class='data'>平均</th></tr>\n");
	printf("<tr><td class='dataVar'>状态变化率:&nbsp;&nbsp;</td><td class='dataVal'>%.2f%%</td><td class='dataVal'>%.2f%%</td><td class='dataVal'>%.2f%%</td></tr>\n", min_host_percent_change_b, max_host_percent_change_b, (double)((double)total_host_percent_change_b / (double)total_passive_host_checks));

	printf("</TABLE>\n");
	printf("</TD></TR>\n");
	printf("</TABLE>\n");

	printf("</td>\n");
	printf("</tr>\n");



	/***** CHECK STATS *****/

	printf("<tr>\n");
	printf("<td valign=center><div class='perfTypeTitle'>检查统计:</div></td>\n");
	printf("<td valign=top colspan='2'>\n");


	printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0>\n");
	printf("<TR><TD class='stateInfoTable1'>\n");
	printf("<TABLE BORDER=0>\n");

	printf("<tr class='data'><th class='data'>类型</th><th class='data'>最近1分钟</th><th class='data'>最近5分钟</th><th class='data'>最近15分钟</th></tr>\n");
	printf("<tr><td class='dataVar'>安排主动主机检查</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td></tr>", program_stats[ACTIVE_SCHEDULED_HOST_CHECK_STATS][0], program_stats[ACTIVE_SCHEDULED_HOST_CHECK_STATS][1], program_stats[ACTIVE_SCHEDULED_HOST_CHECK_STATS][2]);
	printf("<tr><td class='dataVar'>按需主动主机检查</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td></tr>", program_stats[ACTIVE_ONDEMAND_HOST_CHECK_STATS][0], program_stats[ACTIVE_ONDEMAND_HOST_CHECK_STATS][1], program_stats[ACTIVE_ONDEMAND_HOST_CHECK_STATS][2]);
	printf("<tr><td class='dataVar'>并行主机检查</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td></tr>", program_stats[PARALLEL_HOST_CHECK_STATS][0], program_stats[PARALLEL_HOST_CHECK_STATS][1], program_stats[PARALLEL_HOST_CHECK_STATS][2]);
	printf("<tr><td class='dataVar'>串行主机检查</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td></tr>", program_stats[SERIAL_HOST_CHECK_STATS][0], program_stats[SERIAL_HOST_CHECK_STATS][1], program_stats[SERIAL_HOST_CHECK_STATS][2]);
	printf("<tr><td class='dataVar'>缓存主机检查</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td></tr>", program_stats[ACTIVE_CACHED_HOST_CHECK_STATS][0], program_stats[ACTIVE_CACHED_HOST_CHECK_STATS][1], program_stats[ACTIVE_CACHED_HOST_CHECK_STATS][2]);
	printf("<tr><td class='dataVar'>被动主机检查</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td></tr>", program_stats[PASSIVE_HOST_CHECK_STATS][0], program_stats[PASSIVE_HOST_CHECK_STATS][1], program_stats[PASSIVE_HOST_CHECK_STATS][2]);

	printf("<tr><td class='dataVar'>安排主动服务检查</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td></tr>", program_stats[ACTIVE_SCHEDULED_SERVICE_CHECK_STATS][0], program_stats[ACTIVE_SCHEDULED_SERVICE_CHECK_STATS][1], program_stats[ACTIVE_SCHEDULED_SERVICE_CHECK_STATS][2]);
	printf("<tr><td class='dataVar'>按需主动服务检查</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td></tr>", program_stats[ACTIVE_ONDEMAND_SERVICE_CHECK_STATS][0], program_stats[ACTIVE_ONDEMAND_SERVICE_CHECK_STATS][1], program_stats[ACTIVE_ONDEMAND_SERVICE_CHECK_STATS][2]);
	printf("<tr><td class='dataVar'>缓存服务检查</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td></tr>", program_stats[ACTIVE_CACHED_SERVICE_CHECK_STATS][0], program_stats[ACTIVE_CACHED_SERVICE_CHECK_STATS][1], program_stats[ACTIVE_CACHED_SERVICE_CHECK_STATS][2]);
	printf("<tr><td class='dataVar'>被动服务检查</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td></tr>", program_stats[PASSIVE_SERVICE_CHECK_STATS][0], program_stats[PASSIVE_SERVICE_CHECK_STATS][1], program_stats[PASSIVE_SERVICE_CHECK_STATS][2]);

	printf("<tr><td class='dataVar'>额外命令</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td></tr>", program_stats[EXTERNAL_COMMAND_STATS][0], program_stats[EXTERNAL_COMMAND_STATS][1], program_stats[EXTERNAL_COMMAND_STATS][2]);

	printf("</TABLE>\n");
	printf("</TD></TR>\n");
	printf("</TABLE>\n");

	printf("</td>\n");
	printf("</tr>\n");



	/***** BUFFER STATS *****/

	printf("<tr>\n");
	printf("<td valign=center><div class='perfTypeTitle'>缓冲区利用率:</div></td>\n");
	printf("<td valign=top colspan='2'>\n");


	printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0>\n");
	printf("<TR><TD class='stateInfoTable1'>\n");
	printf("<TABLE BORDER=0>\n");

	printf("<tr class='data'><th class='data'>类型</th><th class='data'>使用</th><th class='data'>最大使用</th><th class='data'>可用总量</th></tr>\n");
	printf("<tr><td class='dataVar'>额外命令&nbsp;</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td><td class='dataVal'>%d</td></tr>", buffer_stats[0][1], buffer_stats[0][2], buffer_stats[0][0]);

	printf("</TABLE>\n");
	printf("</TD></TR>\n");
	printf("</TABLE>\n");

	/* make sure gcc3 won't hit here */
#ifndef GCCTOOOLD
	if (event_profiling_enabled) {
		printf("<tr>\n");
		printf("<td valign=center><div class='perfTypeTitle'>事件分析:</div></td>\n");
		printf("<td valign=top colspan='2'>\n");

		printf("<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=0>\n");
		printf("<TR><TD class='stateInfoTable1'>\n");
		printf("<TABLE BORDER=0>\n");


		printf("<tr class='data'><th class='data'>事件分析数据:</th><th class='data'>total seconds spent</th><th class='data'>事件数目</th><th class='data'>avg time per event</th><th class='data'>事件/秒</th></tr>\n");
		while (p) {
			name = p->name;
			count = p->count;
			elapsed = p->elapsed;
			t = profile_object_find_by_name("EVENT_LOOP_COMPLETION");
			total_time = t->elapsed;

			printf("<tr><td class='dataVar'>%s&nbsp;</td><td class='dataVal'>%.2f</td><td class='dataVal'>%d</td><td class='dataVal'>%.3f</td><td class='dataVal'>%.3f</td></tr>", name, elapsed, count, safe_divide(elapsed, count, 0), safe_divide(total_time, count, 1));
			p = p->next;
		}


		printf("</TABLE>\n");
		printf("</TD></TR>\n");
		printf("</TABLE>\n");
	}
#endif


	printf("</td>\n");
	printf("</tr>\n");



	printf("</table>\n");


	printf("</div>\n");

	return;
}

void show_comments(int type) {
	host *temp_host = NULL;
	service *temp_service = NULL;
	int total_comments = 0;
	char *bg_class = "";
	int odd = 1;
	char date_time[MAX_DATETIME_LENGTH];
	comment *temp_comment;
	char *comment_type;
	char expire_time[MAX_DATETIME_LENGTH];
	int colspan = 8;
	int json_start = TRUE;

	/* define colspan */
	if (display_type == DISPLAY_COMMENTS)
		colspan = (type != SERVICE_COMMENT) ? colspan + 1 : colspan + 2;

	if (is_authorized_for_comments_read_only(&current_authdata) == TRUE)
		colspan--;

	if (content_type == JSON_CONTENT) {
		if (type == HOST_COMMENT)
			printf("\"主机注释\": [\n");
		if (type == SERVICE_COMMENT)
			printf("\"服务注释\": [\n");
	} else if (content_type == CSV_CONTENT) {
		/* csv header */
		if (display_type == DISPLAY_COMMENTS && type == HOST_COMMENT) {
			printf("%s主机名称%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s服务%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		}
		if (display_type != DISPLAY_COMMENTS || (display_type == DISPLAY_COMMENTS && type == HOST_COMMENT)) {
			printf("%s时间%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
			printf("%s编辑者%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
			printf("%s注释%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
			printf("%s注释ID%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
			printf("%s持久性%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
			printf("%s类型%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
			printf("%s逾期%s\n",csv_data_enclosure,csv_data_enclosure);
		}
	} else {
		printf("<A NAME=%sCOMMENTS></A>\n", (type == HOST_COMMENT) ? "HOST" : "SERVICE");
		printf("<TABLE BORDER=0 CLASS='comment' style='padding:0px;margin-bottom: -6px;'><TR><TD width='33%%'></TD><TD width='33%%'><DIV CLASS='commentTitle'>%s注释</DIV></TD><TD width='33%%'>", (type == HOST_COMMENT) ? "主机" : "服务");

		/* add export to csv, json, link */
		printf("<DIV style='padding-right:6px;' class='csv_export_link'>");
		if (display_type != DISPLAY_COMMENTS)
			print_export_link(CSV_CONTENT, EXTINFO_CGI, "csvtype=comment");
		else if (type == HOST_COMMENT) {
			print_export_link(CSV_CONTENT, EXTINFO_CGI, "csvtype=comment");
			print_export_link(JSON_CONTENT, EXTINFO_CGI, NULL);
			print_export_link(HTML_CONTENT, EXTINFO_CGI, NULL);
		}
		printf("</div>");

		printf("</TD></TR></TABLE>\n");

		printf("<form name='tableform%scomment' id='tableform%scomment' action='%s' method='POST' onkeypress='var key = (window.event) ? event.keyCode : event.which; return (key != 13);'>", (type == HOST_COMMENT) ? "host" : "service", (type == HOST_COMMENT) ? "host" : "service", CMD_CGI);
		printf("<input type=hidden name=buttonCheckboxChecked>");
		printf("<input type=hidden name='cmd_typ' value=%d>", (type == HOST_COMMENT) ? CMD_DEL_HOST_COMMENT : CMD_DEL_SVC_COMMENT);

		printf("<TABLE BORDER=0 CLASS='comment'>\n");

		printf("<TR><TD colspan='%d' align='right'>", colspan);

		if (display_type == DISPLAY_COMMENTS && type == HOST_COMMENT) {
			printf("<table width='100%%' cellspacing=0 cellpadding=0><tr><td width='33%%'></td><td width='33%%' nowrap>");
			printf("<div class='page_selector'>\n");
			printf("<div id='page_navigation_copy'></div>\n");
			page_limit_selector(result_start);
			printf("</div>\n");
			printf("</td><td width='33%%' align='right'>\n");
		}

		if (is_authorized_for_comments_read_only(&current_authdata) == FALSE)
			printf("<input type='submit' name='CommandButton' value='删除注释' disabled=\"disabled\">");

		if (display_type == DISPLAY_COMMENTS && type == HOST_COMMENT)
			printf("</td></tr></table>");

		printf("</TD></TR>\n");

		printf("<TR CLASS='comment'>");
		if (display_type == DISPLAY_COMMENTS) {
			printf("<TH CLASS='comment'>主机名称</TH>");
			if (type == SERVICE_COMMENT)
				printf("<TH CLASS='comment'>服务</TH>");
		}
		printf("<TH CLASS='comment'>输入时间</TH><TH CLASS='comment'>编辑者</TH><TH CLASS='comment'>注释</TH><TH CLASS='comment'>注释ID</TH><TH CLASS='comment'>持久性</TH><TH CLASS='comment'>类型</TH><TH CLASS='comment'>逾期</TH>");
		if (is_authorized_for_comments_read_only(&current_authdata) == FALSE)
			printf("<TH CLASS='comment' nowrap>动作&nbsp;&nbsp;<input type='checkbox' value='全选' onclick=\"checkAll(\'tableform%scomment\');isValidForSubmit(\'tableform%scomment\');\"></TH>", (type == HOST_COMMENT) ? "host" : "service", (type == HOST_COMMENT) ? "host" : "service");
		printf("</TR>\n");
	}

	/* display all the service comments */
	for (temp_comment = comment_list, total_comments = 0; temp_comment != NULL; temp_comment = temp_comment->next) {

		if (type == HOST_COMMENT && temp_comment->comment_type != HOST_COMMENT)
			continue;

		if (type == SERVICE_COMMENT && temp_comment->comment_type != SERVICE_COMMENT)
			continue;

		if (display_type != DISPLAY_COMMENTS) {
			/* if not our host -> continue */
			if (strcmp(temp_comment->host_name, host_name))
				continue;

			if (type == SERVICE_COMMENT) {
				/* if not our service -> continue */
				if (strcmp(temp_comment->service_description, service_desc))
					continue;
			}
		} else {
			temp_host = find_host(temp_comment->host_name);

			/* make sure the user has rights to view host information */
			if (is_authorized_for_host(temp_host, &current_authdata) == FALSE)
				continue;

			if (type == SERVICE_COMMENT) {
				temp_service = find_service(temp_comment->host_name, temp_comment->service_description);

				/* make sure the user has rights to view service information */
				if (is_authorized_for_service(temp_service, &current_authdata) == FALSE)
					continue;
			}
		}

		if (result_limit != 0  && (((total_entries + 1) < result_start) || (total_entries >= ((result_start + result_limit) - 1)))) {
			total_entries++;
			continue;
		}

		displayed_entries++;
		total_entries++;

		if (odd) {
			odd = 0;
			bg_class = "commentOdd";
		} else {
			odd = 1;
			bg_class = "commentEven";
		}

		switch (temp_comment->entry_type) {
		case USER_COMMENT:
			comment_type = "用户";
			break;
		case DOWNTIME_COMMENT:
			comment_type = "宕机安排";
			break;
		case FLAPPING_COMMENT:
			comment_type = "抖动检测";
			break;
		case ACKNOWLEDGEMENT_COMMENT:
			comment_type = "确认";
			break;
		default:
			comment_type = "?";
		}

		get_time_string(&temp_comment->entry_time, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
		get_time_string(&temp_comment->expire_time, expire_time, (int)sizeof(date_time), SHORT_DATE_TIME);

		if (content_type == JSON_CONTENT) {
			// always add a comma, except for the first line
			if (json_start == FALSE)
				printf(",\n");
			json_start = FALSE;

			printf("{ ");
			if (display_type == DISPLAY_COMMENTS) {
				printf("\"主机名称\": \"%s\", ", json_encode(temp_host->name));
				printf("\"主机显示名称\": \"%s\", ", (temp_host->display_name != NULL) ? json_encode(temp_host->display_name) : json_encode(temp_host->name));
				if (type == SERVICE_COMMENT) {
					printf("\"服务描述\": \"%s\", ", json_encode(temp_service->description));
					printf("\"服务显示名称\": \"%s\", ", (temp_service->display_name != NULL) ? json_encode(temp_service->display_name) : json_encode(temp_service->description));
				}
			}
			 printf("\"输入时间\": \"%s\", ",date_time);
			printf("\"编辑者\": \"%s\", ",json_encode(temp_comment->author));
			printf("\"注释\": \"%s\", ",json_encode(temp_comment->comment_data));
			printf("\"注释id\": %lu, ",temp_comment->comment_id);
			printf("\"持久性\": %s, ",(temp_comment->persistent==TRUE)?"true":"false");
			printf("\"注释类型\": \"%s\", ",comment_type);
			if (temp_comment->expires == TRUE)
				printf("\"逾期\": null }");
			else
				printf("\"逾期\": \"%s\" }", expire_time);
		} else if (content_type == CSV_CONTENT) {
			if (display_type == DISPLAY_COMMENTS) {
				printf("%s%s%s%s", csv_data_enclosure, temp_host->name, csv_data_enclosure, csv_delimiter);
				if (type == SERVICE_COMMENT)
					printf("%s%s%s%s", csv_data_enclosure, temp_service->description, csv_data_enclosure, csv_delimiter);
				else
					printf("%s%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			}
			printf("%s%s%s%s", csv_data_enclosure, date_time, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, temp_comment->author, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, temp_comment->comment_data, csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s", csv_data_enclosure, temp_comment->comment_id, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_comment->persistent) ? "是" : "否", csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, comment_type, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s\n", csv_data_enclosure, (temp_comment->expires == TRUE) ? expire_time : "无", csv_data_enclosure);
		} else {
			printf("<tr CLASS='%s' onClick=\"toggle_checkbox('comment_%lu','tableform%scomment');\">", bg_class, temp_comment->comment_id, (type == HOST_COMMENT) ? "host" : "service");
			if (display_type == DISPLAY_COMMENTS) {
				printf("<td><A HREF='%s?type=%d&host=%s'>%s</A></td>", EXTINFO_CGI, DISPLAY_HOST_INFO, url_encode(temp_comment->host_name), (temp_host->display_name != NULL) ? temp_host->display_name : temp_host->name);
				if (type == SERVICE_COMMENT) {
					printf("<td><A HREF='%s?type=%d&host=%s", EXTINFO_CGI, DISPLAY_SERVICE_INFO, url_encode(temp_comment->host_name));
					printf("&service=%s'>%s</A></td>", url_encode(temp_comment->service_description), (temp_service->display_name != NULL) ? temp_service->display_name : temp_service->description);
				}
			}
			printf("<td name='comment_time'>%s</td><td name='comment_author'>%s</td><td name='comment_data'>%s</td><td name='comment_id'>%lu</td><td name='comment_persist'>%s</td><td name='comment_type'>%s</td><td name='comment_expire'>%s</td>", date_time, temp_comment->author, temp_comment->comment_data, temp_comment->comment_id, (temp_comment->persistent) ? "是" : "否", comment_type, (temp_comment->expires == TRUE) ? expire_time : "无");
			if (is_authorized_for_comments_read_only(&current_authdata) == FALSE) {
				printf("<td align='center'><a href='%s?cmd_typ=%d&com_id=%lu'><img src='%s%s' border=0 ALT='删除该注释' TITLE=删除该注释'></a>", CMD_CGI, (type == HOST_COMMENT) ? CMD_DEL_HOST_COMMENT : CMD_DEL_SVC_COMMENT, temp_comment->comment_id, url_images_path, DELETE_ICON);
				printf("<input type='checkbox' onClick=\"toggle_checkbox('comment_%lu','tableform%scomment');\" name='com_id' id='comment_%lu' value='%lu'></td>", temp_comment->comment_id, (type == HOST_COMMENT) ? "host" : "service", temp_comment->comment_id, temp_comment->comment_id);
			}
			printf("</tr>\n");
		}
		total_comments++;
	}

	/* see if this host or service has any comments associated with it */
	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT) {
		if (total_comments == 0 && total_entries == 0) {
			printf("<TR CLASS='commentOdd'><TD align='center' COLSPAN='%d'>", colspan);
			if (display_type == DISPLAY_COMMENTS)
				printf("没有%s注释", (type == HOST_COMMENT) ? "主机" : "服务");
			else
				printf("该%s无关联注释", (type == HOST_COMMENT) ? "主机" : "服务");
			printf("</TD></TR>\n");
		}

		if (display_type == DISPLAY_COMMENTS && type == SERVICE_COMMENT) {
			printf("<TR><TD colspan='%d'>\n", colspan);
			page_num_selector(result_start, total_entries, displayed_entries);
			printf("</TD></TR>\n");
		}

		printf("</TABLE>\n");
		printf("<script language='javascript' type='text/javascript'>\n");
		printf("document.tableform%scomment.buttonCheckboxChecked.value = 'false';\n", (type == HOST_COMMENT) ? "host" : "service");
		printf("checked = true;\n");
		printf("checkAll(\"tableform%scomment\");\n", (type == HOST_COMMENT) ? "host" : "service");
		printf("checked = false;\n");
		printf("</script>\n");
		printf("</FORM>\n");
	}
	if (content_type == JSON_CONTENT)
		printf("]");

	return;
}

/* shows service and host scheduled downtime */
void show_downtime(int type) {
	char *bg_class = "";
	char date_time[MAX_DATETIME_LENGTH];
	scheduled_downtime *temp_downtime;
	host *temp_host = NULL;
	service *temp_service = NULL;
	int days;
	int hours;
	int minutes;
	int seconds;
	int odd = 0;
	int total_downtime = 0;
	int colspan = 12;
	int json_start = TRUE;

	/* define colspan */
	if (display_type == DISPLAY_DOWNTIME)
		colspan = (type != SERVICE_DOWNTIME) ? colspan + 1 : colspan + 2;

	if (is_authorized_for_downtimes_read_only(&current_authdata) == TRUE)
		colspan--;

	if (content_type == JSON_CONTENT) {
		if (type == HOST_DOWNTIME)
			printf("\"主机宕机\": [\n");
		if (type == SERVICE_DOWNTIME)
			printf("\"服务宕机\": [\n");
	} else if (content_type == CSV_CONTENT) {
		/* csv header */
		if (display_type == DISPLAY_DOWNTIME && type == HOST_DOWNTIME) {
			printf("%s主机名称%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s服务%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		}
		if (display_type != DISPLAY_DOWNTIME || (display_type == DISPLAY_DOWNTIME && type == HOST_DOWNTIME)) {
			printf("%s输入时间%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s编辑者%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s注释%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s开始时间%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s结束时间%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s类型%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s触发时间%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s持续时间%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s生效的%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s宕机ID%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			printf("%s触发ID%s\n", csv_data_enclosure, csv_data_enclosure);
		}
	} else {
		printf("<A NAME=%sDOWNTIME></A>\n", (type == HOST_DOWNTIME) ? "HOST" : "SERVICE");
		printf("<TABLE BORDER=0 CLASS='comment' style='padding:0px;margin-bottom: -6px;'><TR><TD width='33%%'></TD><TD width='33%%'><DIV CLASS='commentTitle'>安排%s宕机</DIV></TD><TD width='33%%'>", (type == HOST_DOWNTIME) ? "主机" : "服务");

		/* add export to csv, json, link */
		printf("<DIV style='padding-right:6px;' class='csv_export_link'>");
		if (display_type != DISPLAY_DOWNTIME)
			print_export_link(CSV_CONTENT, EXTINFO_CGI, "csvtype=downtime");
		else if (type == HOST_DOWNTIME) {
			print_export_link(CSV_CONTENT, EXTINFO_CGI, "csvtype=downtime");
			print_export_link(JSON_CONTENT, EXTINFO_CGI, NULL);
			print_export_link(HTML_CONTENT, EXTINFO_CGI, NULL);
		}
		printf("</div>");

		printf("</TD></TR></TABLE>\n");

		printf("<form name='tableform%sdowntime' id='tableform%sdowntime' action='%s' method='POST' onkeypress='var key = (window.event) ? event.keyCode : event.which; return (key != 13);'>", (type == HOST_DOWNTIME) ? "host" : "service", (type == HOST_DOWNTIME) ? "host" : "service", CMD_CGI);
		printf("<input type=hidden name=buttonCheckboxChecked>");
		printf("<input type=hidden name='cmd_typ' value=%d>", (type == HOST_DOWNTIME) ? CMD_DEL_HOST_DOWNTIME : CMD_DEL_SVC_DOWNTIME);

		printf("<TABLE BORDER=0 CLASS='downtime'>\n");

		printf("<TR><TD colspan='%d' align='right'>", colspan);

		if (display_type == DISPLAY_DOWNTIME && type == HOST_DOWNTIME) {
			printf("<table width='100%%' cellspacing=0 cellpadding=0><tr><td width='33%%'></td><td width='33%%' nowrap>");
			printf("<div class='page_selector'>\n");
			printf("<div id='page_navigation_copy'></div>\n");
			page_limit_selector(result_start);
			printf("</div>\n");
			printf("</td><td width='33%%' align='right'>\n");
		}

		if (is_authorized_for_downtimes_read_only(&current_authdata) == FALSE)
			printf("<input type='submit' name='CommandButton' value='移除宕机' disabled=\"disabled\">");

		if (display_type == DISPLAY_DOWNTIME && type == HOST_DOWNTIME)
			printf("</td></tr></table>");

		printf("</TD></TR>\n");

		printf("<TR CLASS='downtime'>");
		if (display_type == DISPLAY_DOWNTIME) {
			printf("<TH CLASS='downtime'>主机名称</TH>");
			if (type == SERVICE_DOWNTIME)
				printf("<TH CLASS='downtime'>服务</TH>");
		}
		printf("<TH CLASS='downtime'>输入时间</TH><TH CLASS='downtime'>编辑者</TH><TH CLASS='downtime'>注释</TH><TH CLASS='downtime'>开始时间</TH><TH CLASS='downtime'>结束时间</TH><TH CLASS='downtime'>类型</TH><TH CLASS='downtime'>触发时间</TH><TH CLASS='downtime'>持续时间</TH><TH CLASS='downtime'>生效的</TH><TH CLASS='downtime'>宕机ID</TH><TH CLASS='downtime'>触发ID</TH>");
		if (is_authorized_for_downtimes_read_only(&current_authdata) == FALSE)
			printf("<TH CLASS='comment' nowrap>动作&nbsp;&nbsp;<input type='checkbox' value='全部' onclick=\"checkAll(\'tableform%sdowntime\');isValidForSubmit(\'tableform%sdowntime\');\"></TH>", (type == HOST_DOWNTIME) ? "host" : "service", (type == HOST_DOWNTIME) ? "host" : "service");
		printf("</TR>\n");
	}

	/* display all the downtime */
	for (temp_downtime = scheduled_downtime_list, total_downtime = 0; temp_downtime != NULL; temp_downtime = temp_downtime->next) {

		if (type == HOST_DOWNTIME && temp_downtime->type != HOST_DOWNTIME)
			continue;

		if (type == SERVICE_DOWNTIME && temp_downtime->type != SERVICE_DOWNTIME)
			continue;

		if (display_type != DISPLAY_DOWNTIME) {
			/* if not our host -> continue */
			if (strcmp(temp_downtime->host_name, host_name))
				continue;

			if (type == SERVICE_DOWNTIME) {
				/* if not our service -> continue */
				if (strcmp(temp_downtime->service_description, service_desc))
					continue;
			}
		} else {
			temp_host = find_host(temp_downtime->host_name);

			/* make sure the user has rights to view host information */
			if (is_authorized_for_host(temp_host, &current_authdata) == FALSE)
				continue;

			if (type == SERVICE_DOWNTIME) {
				temp_service = find_service(temp_downtime->host_name, temp_downtime->service_description);

				/* make sure the user has rights to view service information */
				if (is_authorized_for_service(temp_service, &current_authdata) == FALSE)
					continue;
			}
		}

		if (result_limit != 0  && (((total_entries + 1) < result_start) || (total_entries >= ((result_start + result_limit) - 1)))) {
			total_entries++;
			continue;
		}

		displayed_entries++;
		total_entries++;

		if (odd) {
			odd = 0;
			bg_class = "downtimeOdd";
		} else {
			odd = 1;
			bg_class = "downtimeEven";
		}

		if (content_type == JSON_CONTENT) {
			// always add a comma, except for the first line
			if (json_start == FALSE)
				printf(",\n");
			json_start = FALSE;

			printf("{ ");
			if (display_type == DISPLAY_DOWNTIME) {
				printf("\"主机名称\": \"%s\", ", json_encode(temp_host->name));
				printf("\"主机显示名称\": \"%s\", ", (temp_host->display_name != NULL) ? json_encode(temp_host->display_name) : json_encode(temp_host->name));
				if (type == SERVICE_DOWNTIME) {
					printf("\"服务描述\": \"%s\", ", json_encode(temp_service->description));
					printf("\"服务显示名称\": \"%s\", ", (temp_service->display_name != NULL) ? json_encode(temp_service->display_name) : json_encode(temp_service->description));
				}
			}
		} else if (content_type == CSV_CONTENT) {
			if (display_type == DISPLAY_DOWNTIME) {
				printf("%s%s%s%s", csv_data_enclosure, temp_host->name, csv_data_enclosure, csv_delimiter);
				if (type == SERVICE_DOWNTIME)
					printf("%s%s%s%s", csv_data_enclosure, temp_service->description, csv_data_enclosure, csv_delimiter);
				else
					printf("%s%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
			}
		} else {
			printf("<tr CLASS='%s' onClick=\"toggle_checkbox('downtime_%lu','tableform%sdowntime');\">", bg_class, temp_downtime->downtime_id, (type == HOST_DOWNTIME) ? "host" : "service");
			if (display_type == DISPLAY_DOWNTIME) {
				printf("<td CLASS='%s'><A HREF='%s?type=%d&host=%s'>%s</A></td>", bg_class, EXTINFO_CGI, DISPLAY_HOST_INFO, url_encode(temp_downtime->host_name), (temp_host->display_name != NULL) ? temp_host->display_name : temp_host->name);
				if (type == SERVICE_DOWNTIME) {
					printf("<td CLASS='%s'><A HREF='%s?type=%d&host=%s", bg_class, EXTINFO_CGI, DISPLAY_SERVICE_INFO, url_encode(temp_downtime->host_name));
					printf("&service=%s'>%s</A></td>", url_encode(temp_downtime->service_description), (temp_service->display_name != NULL) ? temp_service->display_name : temp_service->description);
				}
			}
		}

		get_time_string(&temp_downtime->entry_time, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
		if (content_type == JSON_CONTENT) {
			printf("\"输入时间\": \"%s\", ", date_time);
			if (temp_downtime->author == NULL)
				printf("\"编辑者\": null, ");
			else
				printf("\"编辑者\": \"%s\", ", json_encode(temp_downtime->author));
			if (temp_downtime->author == NULL)
				printf("\"注释\": null, ");
			else
				printf("\"注释\": \"%s\", ", json_encode(temp_downtime->comment));
		} else if (content_type == CSV_CONTENT) {
			printf("%s%s%s%s", csv_data_enclosure, date_time, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_downtime->author == NULL) ? "无" : temp_downtime->author, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_downtime->comment == NULL) ? "无" : temp_downtime->comment, csv_data_enclosure, csv_delimiter);
		} else {
			printf("<td CLASS='%s'>%s</td>", bg_class, date_time);
			printf("<td CLASS='%s'>%s</td>", bg_class, (temp_downtime->author == NULL) ? "无" : temp_downtime->author);
			printf("<td CLASS='%s'>%s</td>", bg_class, (temp_downtime->comment == NULL) ? "无" : temp_downtime->comment);
		}

		get_time_string(&temp_downtime->start_time, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
		if (content_type == JSON_CONTENT)
			printf("\"开始时间\": \"%s\", ", date_time);
		else if (content_type == CSV_CONTENT)
			printf("%s%s%s%s", csv_data_enclosure, date_time, csv_data_enclosure, csv_delimiter);
		else
			printf("<td CLASS='%s'>%s</td>", bg_class, date_time);

		get_time_string(&temp_downtime->end_time, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
		if (content_type == JSON_CONTENT) {
			printf("\"结束时间\": \"%s\", ", date_time);
			printf("\"类型\": \"%s\", ", (temp_downtime->fixed == TRUE) ? "固定" : "可变");
		} else if (content_type == CSV_CONTENT) {
			printf("%s%s%s%s", csv_data_enclosure, date_time, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_downtime->fixed == TRUE) ? "固定" : "可变", csv_data_enclosure, csv_delimiter);
		} else {
			printf("<td CLASS='%s'>%s</td>", bg_class, date_time);
			printf("<td CLASS='%s'>%s</td>", bg_class, (temp_downtime->fixed == TRUE) ?  "固定" : "可变");
		}

		get_time_string(&temp_downtime->trigger_time, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
		if (content_type == JSON_CONTENT) {
			if (temp_downtime->trigger_time != 0)
				printf("\"触发时间\": \"%s\", ", date_time);
			else
				printf("\"触发时间\": null, ");
		} else if (content_type == CSV_CONTENT) {
			printf("%s%s%s%s", csv_data_enclosure, (temp_downtime->trigger_time != 0) ? date_time : "无", csv_data_enclosure, csv_delimiter);
		} else {
			printf("<td CLASS='%s'>%s</td>", bg_class, (temp_downtime->trigger_time != 0) ? date_time : "无");
		}

		get_time_breakdown(temp_downtime->duration, &days, &hours, &minutes, &seconds);
		if (content_type == JSON_CONTENT) {
			printf("\"持续时间\": \"%2d天%2d时%2d分%2d秒\", ", days, hours, minutes, seconds);
			printf("\"受影响\": %s, ", (temp_downtime->is_in_effect == TRUE) ? "true" : "false");
			printf("\"宕机id\": %lu, ", temp_downtime->downtime_id);
			printf("\"触发id\": \"");
		} else if (content_type == CSV_CONTENT) {
			printf("%s%2d天%2d时%2d分%2d秒%s%s", csv_data_enclosure, days, hours, minutes, seconds, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_downtime->is_in_effect == TRUE) ? "true" : "false", csv_data_enclosure, csv_delimiter);
			printf("%s%lu%s%s", csv_data_enclosure, temp_downtime->downtime_id, csv_data_enclosure, csv_delimiter);
			printf("%s", csv_data_enclosure);
		} else {
			printf("<td CLASS='%s'>%2d天%2d时%2d分%2d秒</td>", bg_class, days, hours, minutes, seconds);
			printf("<td CLASS='%s'>%s</td>", bg_class, (temp_downtime->is_in_effect == TRUE) ? "True" : "False");
			printf("<td CLASS='%s'>%lu</td>", bg_class, temp_downtime->downtime_id);
			printf("<td CLASS='%s'>", bg_class);
		}
		if (temp_downtime->triggered_by == 0) {
			if (content_type == JSON_CONTENT)
				printf("空");
			else
				printf("无");
		} else
			printf("%lu", temp_downtime->triggered_by);

		if (content_type == JSON_CONTENT) {
			printf("\" }\n");
		} else if (content_type == CSV_CONTENT) {
			printf("%s\n", csv_data_enclosure);
		} else {
			printf("</td>\n");
			if (is_authorized_for_downtimes_read_only(&current_authdata) == FALSE) {
				printf("<td align='center' CLASS='%s'><a href='%s?cmd_typ=%d", bg_class, CMD_CGI, (type == HOST_DOWNTIME) ? CMD_DEL_HOST_DOWNTIME : CMD_DEL_SVC_DOWNTIME);
				printf("&down_id=%lu'><img src='%s%s' border=0 ALT='删除/取消该安排宕机条目' TITLE='删除/取消该安排宕机条目'></a>", temp_downtime->downtime_id, url_images_path, DELETE_ICON);
				printf("<input type='checkbox' onClick=\"toggle_checkbox('downtime_%lu','tableform%sdowntime');\" name='down_id' id='downtime_%lu' value='%lu'></td>", temp_downtime->downtime_id, (type == HOST_DOWNTIME) ? "host" : "service", temp_downtime->downtime_id, temp_downtime->downtime_id);
			}
			printf("</tr>\n");
		}
		total_downtime++;
	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT) {
		if (total_downtime == 0 && total_entries == 0) {
			printf("<TR CLASS='downtimeOdd'><TD  align='center' COLSPAN=%d>", colspan);
			if (display_type == DISPLAY_DOWNTIME)
				printf("没有安排%s宕机", (type == HOST_DOWNTIME) ? "主机" : "服务");
			else
				printf("没有安排与%s相关的宕机", (type == HOST_DOWNTIME) ? "主机" : "服务");
			printf("</TD></TR>\n");
		}

		if (display_type == DISPLAY_DOWNTIME && type == SERVICE_DOWNTIME) {
			printf("<TR><TD colspan='%d'>\n", colspan);
			page_num_selector(result_start, total_entries, displayed_entries);
			printf("</TD></TR>\n");
		}

		printf("</TABLE>\n");
		printf("<script language='javascript' type='text/javascript'>\n");
		printf("document.tableform%sdowntime.buttonCheckboxChecked.value = 'false';\n", (type == HOST_DOWNTIME) ? "host" : "service");
		printf("checked = true;\n");
		printf("checkAll(\"tableform%sdowntime\");\n", (type == HOST_DOWNTIME) ? "host" : "service");
		printf("checked = false;\n");
		printf("</script>\n");
		printf("</FORM>\n");
	}
	if (content_type == JSON_CONTENT)
		printf("]");

	return;
}

/* shows check scheduling queue */
void show_scheduling_queue(void) {
	sortdata *temp_sortdata;
	host *temp_host = NULL;
	service *temp_service = NULL;
	servicestatus *temp_svcstatus = NULL;
	hoststatus *temp_hststatus = NULL;
	char date_time[MAX_DATETIME_LENGTH];
	char temp_url[MAX_INPUT_BUFFER];
	char service_link[MAX_INPUT_BUFFER];
	char action_link_enable_disable[MAX_INPUT_BUFFER];
	char action_link_schedule[MAX_INPUT_BUFFER];
	char host_native_name[MAX_INPUT_BUFFER];
	char service_native_name[MAX_INPUT_BUFFER];
	char host_display_name[MAX_INPUT_BUFFER];
	char service_display_name[MAX_INPUT_BUFFER];
	char url_encoded_service[MAX_INPUT_BUFFER];
	char url_encoded_host[MAX_INPUT_BUFFER];
	char temp_buffer[MAX_INPUT_BUFFER];
	char *last_check = "", *next_check = "", *type = "";
	int checks_enabled = FALSE;
	int odd = 0;
	char *bgclass = "";
	int json_start = TRUE;

	/* sort hosts and services */
	sort_data(sort_type, sort_option);

	if (content_type == JSON_CONTENT) {
		printf("\"安排队列\": [\n");
	} else if (content_type == CSV_CONTENT) {
		/* csv header line */
		printf("%s主机%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s服务%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s最近检查%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s下一次检查%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s类型%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s主动检查%s\n", csv_data_enclosure, csv_data_enclosure);
	} else {
		printf("<DIV ALIGN=CENTER CLASS='statusSort'>按<b>");
		if (sort_option == SORT_HOSTNAME)
			printf("主机名称");
		else if (sort_option == SORT_SERVICENAME)
			printf("服务名称");
		else if (sort_option == SORT_SERVICESTATUS)
			printf("服务状态");
		else if (sort_option == SORT_LASTCHECKTIME)
			printf("最近检查时间");
		else if (sort_option == SORT_NEXTCHECKTIME)
			printf("下一次检查时间");
		printf("</b>条目排序(%s)\n", (sort_type == SORT_ASCENDING) ? "升序" : "降序");
		printf("</DIV>\n");

		printf("<TABLE BORDER=0 CLASS='queue' align='center'>\n");

		/* add export to csv link */
		printf("<TR><TD colspan='7'>\n");
		printf("<table width='100%%' cellspacing=0 cellpadding=0><tr><td width='15%%'></td><td width='70%%' nowrap>");

		printf("<div class='page_selector'>\n");
		printf("<div id='page_navigation_copy'></div>\n");
		page_limit_selector(result_start);
		printf("</div>\n");

		printf("</td><td width='15%%' align='right'>\n<DIV class='csv_export_link'>\n");
		print_export_link(CSV_CONTENT, EXTINFO_CGI, NULL);
		print_export_link(JSON_CONTENT, EXTINFO_CGI, NULL);
		print_export_link(HTML_CONTENT, EXTINFO_CGI, NULL);
		printf("</DIV>\n");
		printf("</td></tr></table>");
		printf("</TD></TR>\n");

		printf("<TR CLASS='queue'>");

		snprintf(temp_url, sizeof(temp_url) - 1, "%s?type=%d", EXTINFO_CGI, DISPLAY_SCHEDULING_QUEUE);
		temp_url[sizeof(temp_url) - 1] = '\x0';

		if (host_name && *host_name != '\0') {
			strncpy(temp_buffer, temp_url, sizeof(temp_buffer));
			snprintf(temp_url, sizeof(temp_url) - 1, "%s&host=%s", temp_buffer, url_encode(host_name));
			temp_url[sizeof(temp_url) - 1] = '\x0';
		}

		if (service_desc && *service_desc != '\0') {
			strncpy(temp_buffer, temp_url, sizeof(temp_buffer));
			snprintf(temp_url, sizeof(temp_url) - 1, "%s&service=%s", temp_buffer, url_encode(service_desc));
			temp_url[sizeof(temp_url) - 1] = '\x0';
		}

		printf("<TH CLASS='queue'>主机&nbsp;<A HREF='%s&sorttype=%d&sortoption=%d'><IMG SRC='%s%s' BORDER=0 ALT=主机名称排序(升序)' TITLE='主机名称排序(升序)'></A><A HREF='%s&sorttype=%d&sortoption=%d'><IMG SRC='%s%s' BORDER=0 ALT='主机名称排序(降序)' TITLE='主机名称排序(降序)'></A></TH>", temp_url, SORT_ASCENDING, SORT_HOSTNAME, url_images_path, UP_ARROW_ICON, temp_url, SORT_DESCENDING, SORT_HOSTNAME, url_images_path, DOWN_ARROW_ICON);
		printf("<TH CLASS='queue'>服务&nbsp;<A HREF='%s&sorttype=%d&sortoption=%d'><IMG SRC='%s%s' BORDER=0 ALT='服务名称排序(升序)' TITLE='服务名称排序(升序)'></A><A HREF='%s&sorttype=%d&sortoption=%d'><IMG SRC='%s%s' BORDER=0 ALT='服务名称排序(降序)' TITLE='服务名称排序(降序)'></A></TH>", temp_url, SORT_ASCENDING, SORT_SERVICENAME, url_images_path, UP_ARROW_ICON, temp_url, SORT_DESCENDING, SORT_SERVICENAME, url_images_path, DOWN_ARROW_ICON);
		printf("<TH CLASS='queue'>最近检查&nbsp;<A HREF='%s&sorttype=%d&sortoption=%d'><IMG SRC='%s%s' BORDER=0 ALT='最近检查时间排序(升序)' TITLE='最近检查时间排序(升序)'></A><A HREF='%s&sorttype=%d&sortoption=%d'><IMG SRC='%s%s' BORDER=0 ALT='最近检查时间排序(降序)' TITLE='最近检查时间排序(降序)'></A></TH>", temp_url, SORT_ASCENDING, SORT_LASTCHECKTIME, url_images_path, UP_ARROW_ICON, temp_url, SORT_DESCENDING, SORT_LASTCHECKTIME, url_images_path, DOWN_ARROW_ICON);
		printf("<TH CLASS='queue'>下一次检查&nbsp;<A HREF='%s&sorttype=%d&sortoption=%d'><IMG SRC='%s%s' BORDER=0 ALT='下一次检查时间排序(升序)' TITLE='下一次检查时间排序(升序)'></A><A HREF='%s&sorttype=%d&sortoption=%d'><IMG SRC='%s%s' BORDER=0 ALT='下一次检查时间排序(降序)' TITLE='下一次检查时间排序(降序)'></A></TH>", temp_url, SORT_ASCENDING, SORT_NEXTCHECKTIME, url_images_path, UP_ARROW_ICON, temp_url, SORT_DESCENDING, SORT_NEXTCHECKTIME, url_images_path, DOWN_ARROW_ICON);
		printf("<TH CLASS='queue'>类型</TH><TH CLASS='queue'>主动检查</TH><TH CLASS='queue'>动作</TH></TR>\n");
	}

	/* display all services and hosts */
	for (temp_sortdata = sortdata_list; temp_sortdata != NULL; temp_sortdata = temp_sortdata->next) {

		/* skip hosts and services that shouldn't be scheduled */
		if (temp_sortdata->is_service == TRUE) {
			temp_svcstatus = temp_sortdata->svcstatus;
			if (temp_svcstatus->should_be_scheduled == FALSE) {
				/* passive-only checks should appear if they're being forced */
				if (!(temp_svcstatus->checks_enabled == FALSE && temp_svcstatus->next_check != (time_t)0L && (temp_svcstatus->check_options & CHECK_OPTION_FORCE_EXECUTION)))
					continue;
			}
			if (host_name && *host_name != '\0' && strcmp(host_name, temp_svcstatus->host_name))
				continue;

			if (service_desc && *service_desc != '\0' && strcmp(service_desc, temp_svcstatus->description))
				continue;

		} else {
			temp_hststatus = temp_sortdata->hststatus;
			if (temp_hststatus->should_be_scheduled == FALSE) {
				/* passive-only checks should appear if they're being forced */
				if (!(temp_hststatus->checks_enabled == FALSE && temp_hststatus->next_check != (time_t)0L && (temp_hststatus->check_options & CHECK_OPTION_FORCE_EXECUTION)))
					continue;
			}
			if (host_name && *host_name != '\0' && strcmp(host_name, temp_hststatus->host_name))
				continue;

			/* skip host if users just want to see a service */
			if (service_desc && *service_desc != '\0')
				continue;
		}

		/* get the service status */
		if (temp_sortdata->is_service == TRUE) {

			/* find the host */
			temp_host = find_host(temp_svcstatus->host_name);

			if (temp_host == NULL)
				continue;

			/* make sure user has rights to see this... */
			if (is_authorized_for_host(temp_host, &current_authdata) == FALSE)
				continue;

			snprintf(url_encoded_host, sizeof(url_encoded_host) - 1, "%s", url_encode(temp_svcstatus->host_name));
			url_encoded_host[sizeof(url_encoded_host) - 1] = '\x0';

			/* find the service */
			temp_service = find_service(temp_svcstatus->host_name, temp_svcstatus->description);

			/* if we couldn't find the service, go to the next service */
			if (temp_service == NULL)
				continue;

			/* make sure user has rights to see this... */
			if (is_authorized_for_service(temp_service, &current_authdata) == FALSE)
				continue;

			snprintf(url_encoded_service, sizeof(url_encoded_service) - 1, "%s", url_encode(temp_svcstatus->description));
			url_encoded_service[sizeof(url_encoded_service) - 1] = '\x0';

			/* host name */
			snprintf(host_native_name, sizeof(host_native_name) - 1, "%s", temp_svcstatus->host_name);
			host_native_name[sizeof(host_native_name) - 1] = '\x0';
			snprintf(host_display_name, sizeof(host_display_name) - 1, "%s", (temp_host != NULL && temp_host->display_name != NULL) ? temp_host->display_name : temp_hststatus->host_name);
			host_display_name[sizeof(host_display_name) - 1] = '\x0';

			/* service name */
			snprintf(service_native_name, sizeof(service_native_name) - 1, "%s", temp_svcstatus->description);
			service_native_name[sizeof(service_native_name) - 1] = '\x0';
			snprintf(service_display_name, sizeof(service_display_name) - 1, "%s", (temp_service != NULL && temp_service->display_name != NULL) ? temp_service->display_name : temp_svcstatus->description);
			service_display_name[sizeof(service_display_name) - 1] = '\x0';

			/* service link*/
			snprintf(service_link, sizeof(service_link) - 1, "%s?type=%d&host=%s&service=%s", EXTINFO_CGI, DISPLAY_SERVICE_INFO, url_encoded_host, url_encoded_service);
			service_link[sizeof(service_link) - 1] = '\x0';

			/* last check */
			get_time_string(&temp_svcstatus->last_check, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			last_check = (temp_svcstatus->last_check == (time_t)0) ? strdup("N/A") : strdup(date_time);

			/* next check */
			get_time_string(&temp_svcstatus->next_check, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			next_check = (temp_svcstatus->next_check == (time_t)0) ? strdup("N/A") : strdup(date_time);

			/* type */
			if (temp_svcstatus->check_options == CHECK_OPTION_NONE)
				type = "正常";
			else {
				if (temp_svcstatus->check_options & CHECK_OPTION_FORCE_EXECUTION)
					type = "强迫";
				if (temp_svcstatus->check_options & CHECK_OPTION_FRESHNESS_CHECK)
					type = "更新";
				if (temp_svcstatus->check_options & CHECK_OPTION_ORPHAN_CHECK)
					type = "孤立";
			}

			/* active checks */
			checks_enabled = temp_svcstatus->checks_enabled;

			/* action links */
			if (temp_svcstatus->checks_enabled == TRUE)
				snprintf(action_link_enable_disable, sizeof(action_link_enable_disable) - 1, "%s?cmd_typ=%d&host=%s&service=%s", CMD_CGI, CMD_DISABLE_SVC_CHECK, url_encoded_host, url_encoded_service);
			else
				snprintf(action_link_enable_disable, sizeof(action_link_enable_disable) - 1, "%s?cmd_typ=%d&host=%s&service=%s", CMD_CGI, CMD_ENABLE_SVC_CHECK, url_encoded_host, url_encoded_service);
			action_link_enable_disable[sizeof(action_link_enable_disable) - 1] = '\x0';

			snprintf(action_link_schedule, sizeof(action_link_schedule) - 1, "%s?cmd_typ=%d&host=%s&service=%s%s", CMD_CGI, CMD_SCHEDULE_SVC_CHECK, url_encoded_host, url_encoded_service, (temp_svcstatus->checks_enabled == TRUE) ? "&force_check" : "");
			action_link_schedule[sizeof(action_link_schedule) - 1] = '\x0';

			/* get the host status */
		} else {
			/* find the host */
			temp_host = find_host(temp_hststatus->host_name);

			if (temp_host == NULL)
				continue;

			/* make sure user has rights to see this... */
			if (is_authorized_for_host(temp_host, &current_authdata) == FALSE)
				continue;

			snprintf(url_encoded_host, sizeof(url_encoded_host) - 1, "%s", url_encode(temp_hststatus->host_name));
			url_encoded_host[sizeof(url_encoded_host) - 1] = '\x0';

			/* host name */
			snprintf(host_native_name, sizeof(host_native_name) - 1, "%s", temp_hststatus->host_name);
			host_native_name[sizeof(host_native_name) - 1] = '\x0';
			snprintf(host_display_name, sizeof(host_display_name) - 1, "%s", (temp_host != NULL && temp_host->display_name != NULL) ? temp_host->display_name : temp_hststatus->host_name);
			host_display_name[sizeof(host_display_name) - 1] = '\x0';

			/* last check */
			get_time_string(&temp_hststatus->last_check, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			last_check = (temp_hststatus->last_check == (time_t)0) ? strdup("无") : strdup(date_time);

			/* next check */
			get_time_string(&temp_hststatus->next_check, date_time, (int)sizeof(date_time), SHORT_DATE_TIME);
			next_check = (temp_hststatus->next_check == (time_t)0) ? strdup("无") : strdup(date_time);

			/* type */
			if (temp_hststatus->check_options == CHECK_OPTION_NONE)
				type = "正常";
			else {
				if (temp_hststatus->check_options & CHECK_OPTION_FORCE_EXECUTION)
					type = "强制";
				if (temp_hststatus->check_options & CHECK_OPTION_FRESHNESS_CHECK)
					type = "更新";
				if (temp_hststatus->check_options & CHECK_OPTION_ORPHAN_CHECK)
					type = "孤立";
			}

			/* active checks */
			checks_enabled = temp_hststatus->checks_enabled;

			/* action links */
			if (temp_hststatus->checks_enabled == TRUE)
				snprintf(action_link_enable_disable, sizeof(action_link_enable_disable) - 1, "%s?cmd_typ=%d&host=%s", CMD_CGI, CMD_DISABLE_HOST_CHECK, url_encoded_host);
			else
				snprintf(action_link_enable_disable, sizeof(action_link_enable_disable) - 1, "%s?cmd_typ=%d&host=%s", CMD_CGI, CMD_ENABLE_HOST_CHECK, url_encoded_host);
			action_link_enable_disable[sizeof(action_link_enable_disable) - 1] = '\x0';

			snprintf(action_link_schedule, sizeof(action_link_schedule) - 1, "%s?cmd_typ=%d&host=%s%s", CMD_CGI, CMD_SCHEDULE_HOST_CHECK, url_encoded_host, (temp_hststatus->checks_enabled == TRUE) ? "&force_check" : "");
			action_link_schedule[sizeof(action_link_schedule) - 1] = '\x0';
		}

		if (result_limit != 0  && (((total_entries + 1) < result_start) || (total_entries >= ((result_start + result_limit) - 1)))) {
			total_entries++;
			my_free(last_check);
			my_free(next_check);
			continue;
		}

		displayed_entries++;
		total_entries++;

		if (odd) {
			odd = 0;
			bgclass = "Even";
		} else {
			odd = 1;
			bgclass = "Odd";
		}

		if (content_type == JSON_CONTENT) {
			// always add a comma, except for the first line
			if (json_start == FALSE)
				printf(",\n");
			json_start = FALSE;

			printf("{ \"主机名称\": \"%s\", ", json_encode(host_native_name));
			printf("\"主机显示名称\": \"%s\", ", json_encode(host_display_name));
			if (temp_sortdata->is_service == TRUE) {
				printf("\"服务描述\": \"%s\", ", json_encode(service_native_name));
				printf("\"服务显示名称\": \"%s\", ", json_encode(service_display_name));
				printf("\"类型\": \"SERVICE_CHECK\", ");
			} else
				printf("\"类型\": \"HOST_CHECK\", ");

			printf("\"最近检查\": \"%s\", ", last_check);
			printf("\"下一次检查\": \"%s\", ", next_check);
			printf("\"类型\": \"%s\", ", type);
			printf("\"主动检查\": %s }", (checks_enabled == TRUE) ? "true" : "false");
		} else if (content_type == CSV_CONTENT) {
			printf("%s%s%s%s", csv_data_enclosure, host_native_name, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_sortdata->is_service == TRUE) ? service_native_name : "", csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, last_check, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, next_check, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, type, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s\n", csv_data_enclosure, (checks_enabled == TRUE) ? "启用" : "禁用", csv_data_enclosure);
		} else {
			printf("<TR CLASS='queue%s'>", bgclass);

			/* Host */
			printf("<TD CLASS='queue%s'><A HREF='%s?type=%d&host=%s'>%s</A></TD>", bgclass, EXTINFO_CGI, DISPLAY_HOST_INFO, url_encoded_host, html_encode(host_display_name,TRUE));

			/* Service */
			if (temp_sortdata->is_service == TRUE)
				printf("<TD CLASS='queue%s'><A HREF='%s'>%s</A></TD>", bgclass, service_link, html_encode(service_display_name,TRUE));
			else
				printf("<TD CLASS='queue%s'>&nbsp;</TD>", bgclass);

			/* last check */
			printf("<TD CLASS='queue%s'>%s</TD>", bgclass, last_check);

			/* next check */
			printf("<TD CLASS='queue%s'>%s</TD>", bgclass, next_check);

			/* type */
			printf("<TD align='center' CLASS='queue%s'>%s</TD>", bgclass, type);

			/* active checks */
			printf("<TD CLASS='queue%s'>%s</TD>", (checks_enabled == TRUE) ? "ENABLED" : "DISABLED", (checks_enabled == TRUE) ? "启用" : "禁用");

			/* actions */
			printf("<TD align='center' CLASS='queue%s'>", bgclass);
			printf("<a href='%s'><img src='%s%s' border=0 ALT='%s该%s的主动检查' TITLE='%s该%s的主动检查'></a>\n", action_link_enable_disable, url_images_path, (checks_enabled == TRUE) ? DISABLED_ICON : ENABLED_ICON, (checks_enabled == TRUE) ? "禁用" : "启用", (temp_sortdata->is_service == TRUE) ? "服务" : "主机", (checks_enabled == TRUE) ? "禁用" : "启用", (temp_sortdata->is_service == TRUE) ? "服务" : "主机");
			printf("<a href='%s'><img src='%s%s' border=0 ALT='重新安排该%s检查' TITLE='重新安排该%s检查'></a>", action_link_schedule, url_images_path, DELAY_ICON, (temp_sortdata->is_service == TRUE) ? "服务" : "主机", (temp_sortdata->is_service == TRUE) ? "服务" : "主机");

			printf("</TD></TR>\n");
		}

		my_free(last_check);
		my_free(next_check);
	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT) {
		printf("<TR><TD colspan='7'>\n");
		page_num_selector(result_start, total_entries, displayed_entries);
		printf("</TD></TR>\n");
		printf("</TABLE>\n");
	} else if (content_type == JSON_CONTENT)
		printf(" ] \n");

	/* free memory allocated to sorted data list */
	free_sortdata_list();

	return;
}

/* sorts host and service data */
int sort_data(int s_type, int s_option) {
	sortdata *new_sortdata;
	sortdata *last_sortdata;
	sortdata *temp_sortdata;
	servicestatus *temp_svcstatus;
	hoststatus *temp_hststatus;

	if (s_type == SORT_NONE)
		return ERROR;

	/* sort all service status entries */
	for (temp_svcstatus = servicestatus_list; temp_svcstatus != NULL; temp_svcstatus = temp_svcstatus->next) {

		/* allocate memory for a new sort structure */
		new_sortdata = (sortdata *)malloc(sizeof(sortdata));
		if (new_sortdata == NULL)
			return ERROR;

		new_sortdata->is_service = TRUE;
		new_sortdata->svcstatus = temp_svcstatus;
		new_sortdata->hststatus = NULL;

		last_sortdata = sortdata_list;
		for (temp_sortdata = sortdata_list; temp_sortdata != NULL; temp_sortdata = temp_sortdata->next) {

			if (compare_sortdata_entries(s_type, s_option, new_sortdata, temp_sortdata) == TRUE) {
				new_sortdata->next = temp_sortdata;
				if (temp_sortdata == sortdata_list)
					sortdata_list = new_sortdata;
				else
					last_sortdata->next = new_sortdata;
				break;
			} else
				last_sortdata = temp_sortdata;
		}

		if (sortdata_list == NULL) {
			new_sortdata->next = NULL;
			sortdata_list = new_sortdata;
		} else if (temp_sortdata == NULL) {
			new_sortdata->next = NULL;
			last_sortdata->next = new_sortdata;
		}
	}

	/* sort all host status entries */
	for (temp_hststatus = hoststatus_list; temp_hststatus != NULL; temp_hststatus = temp_hststatus->next) {

		/* allocate memory for a new sort structure */
		new_sortdata = (sortdata *)malloc(sizeof(sortdata));
		if (new_sortdata == NULL)
			return ERROR;

		new_sortdata->is_service = FALSE;
		new_sortdata->svcstatus = NULL;
		new_sortdata->hststatus = temp_hststatus;

		last_sortdata = sortdata_list;
		for (temp_sortdata = sortdata_list; temp_sortdata != NULL; temp_sortdata = temp_sortdata->next) {

			if (compare_sortdata_entries(s_type, s_option, new_sortdata, temp_sortdata) == TRUE) {
				new_sortdata->next = temp_sortdata;
				if (temp_sortdata == sortdata_list)
					sortdata_list = new_sortdata;
				else
					last_sortdata->next = new_sortdata;
				break;
			} else
				last_sortdata = temp_sortdata;
		}

		if (sortdata_list == NULL) {
			new_sortdata->next = NULL;
			sortdata_list = new_sortdata;
		} else if (temp_sortdata == NULL) {
			new_sortdata->next = NULL;
			last_sortdata->next = new_sortdata;
		}
	}

	return OK;
}

int compare_sortdata_entries(int s_type, int s_option, sortdata *new_sortdata, sortdata *temp_sortdata) {
	hoststatus *temp_hststatus = NULL;
	servicestatus *temp_svcstatus = NULL;
	time_t last_check[2];
	time_t next_check[2];
	int current_attempt[2];
	int status[2];
	char *host_name[2];
	char *service_description[2];

	if (new_sortdata->is_service == TRUE) {
		temp_svcstatus = new_sortdata->svcstatus;
		last_check[0] = temp_svcstatus->last_check;
		next_check[0] = temp_svcstatus->next_check;
		status[0] = temp_svcstatus->status;
		host_name[0] = temp_svcstatus->host_name;
		service_description[0] = temp_svcstatus->description;
		current_attempt[0] = temp_svcstatus->current_attempt;
	} else {
		temp_hststatus = new_sortdata->hststatus;
		last_check[0] = temp_hststatus->last_check;
		next_check[0] = temp_hststatus->next_check;
		status[0] = temp_hststatus->status;
		host_name[0] = temp_hststatus->host_name;
		service_description[0] = "";
		current_attempt[0] = temp_hststatus->current_attempt;
	}
	if (temp_sortdata->is_service == TRUE) {
		temp_svcstatus = temp_sortdata->svcstatus;
		last_check[1] = temp_svcstatus->last_check;
		next_check[1] = temp_svcstatus->next_check;
		status[1] = temp_svcstatus->status;
		host_name[1] = temp_svcstatus->host_name;
		service_description[1] = temp_svcstatus->description;
		current_attempt[1] = temp_svcstatus->current_attempt;
	} else {
		temp_hststatus = temp_sortdata->hststatus;
		last_check[1] = temp_hststatus->last_check;
		next_check[1] = temp_hststatus->next_check;
		status[1] = temp_hststatus->status;
		host_name[1] = temp_hststatus->host_name;
		service_description[1] = "";
		current_attempt[1] = temp_hststatus->current_attempt;
	}

	if (s_type == SORT_ASCENDING) {

		if (s_option == SORT_LASTCHECKTIME) {
			if (last_check[0] <= last_check[1])
				return TRUE;
			else
				return FALSE;
		}
		if (s_option == SORT_NEXTCHECKTIME) {
			if (next_check[0] <= next_check[1])
				return TRUE;
			else
				return FALSE;
		} else if (s_option == SORT_CURRENTATTEMPT) {
			if (current_attempt[0] <= current_attempt[1])
				return TRUE;
			else
				return FALSE;
		} else if (s_option == SORT_SERVICESTATUS) {
			if (status[0] <= status[1])
				return TRUE;
			else
				return FALSE;
		} else if (s_option == SORT_HOSTNAME) {
			if (strcasecmp(host_name[0], host_name[1]) < 0)
				return TRUE;
			else
				return FALSE;
		} else if (s_option == SORT_SERVICENAME) {
			if (strcasecmp(service_description[0], service_description[1]) < 0)
				return TRUE;
			else
				return FALSE;
		}
	} else {
		if (s_option == SORT_LASTCHECKTIME) {
			if (last_check[0] > last_check[1])
				return TRUE;
			else
				return FALSE;
		}
		if (s_option == SORT_NEXTCHECKTIME) {
			if (next_check[0] > next_check[1])
				return TRUE;
			else
				return FALSE;
		} else if (s_option == SORT_CURRENTATTEMPT) {
			if (current_attempt[0] > current_attempt[1])
				return TRUE;
			else
				return FALSE;
		} else if (s_option == SORT_SERVICESTATUS) {
			if (status[0] > status[1])
				return TRUE;
			else
				return FALSE;
		} else if (s_option == SORT_HOSTNAME) {
			if (strcasecmp(host_name[0], host_name[1]) > 0)
				return TRUE;
			else
				return FALSE;
		} else if (s_option == SORT_SERVICENAME) {
			if (strcasecmp(service_description[0], service_description[1]) > 0)
				return TRUE;
			else
				return FALSE;
		}
	}

	return TRUE;
}

/* free all memory allocated to the sortdata structures */
void free_sortdata_list(void) {
	sortdata *this_sortdata;
	sortdata *next_sortdata;

	/* free memory for the sortdata list */
	for (this_sortdata = sortdata_list; this_sortdata != NULL; this_sortdata = next_sortdata) {
		next_sortdata = this_sortdata->next;
		free(this_sortdata);
	}

	return;
}

/* determines whether or not a specific host is an child of another host */
/* NOTE: this could be expensive in large installations, so use with care! */
int is_host_child_of_host(host *parent_host, host *child_host) {
	host *temp_host;

	/* not enough data */
	if (child_host == NULL)
		return FALSE;

	/* root/top-level hosts */
	if (parent_host == NULL) {
		if (child_host->parent_hosts == NULL)
			return TRUE;

		/* mid-level/bottom hosts */
	} else {

		for (temp_host = host_list; temp_host != NULL; temp_host = temp_host->next) {

			/* skip this host if it is not a child */
			if (is_host_immediate_child_of_host(parent_host, temp_host) == FALSE)
				continue;
			else {
				if (!strcmp(temp_host->name, child_host->name))
					return TRUE;
				else {
					if (is_host_child_of_host(temp_host, child_host) == FALSE)
						continue;

					return TRUE;
				}
			}
		}
	}

	return FALSE;
}

