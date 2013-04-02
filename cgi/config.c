/***********************************************************************
 *
 * CONFIG.C - Icinga Configuration CGI (View Only)
 *
 * Copyright (c) 1999-2009 Ethan Galstad (egalstad@nagios.org)
 * Copyright (c) 2009-2012 Icinga Development Team (http://www.icinga.org)
 *
 * This CGI program will display various configuration information.
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 ***********************************************************************/

#include "../include/config.h"
#include "../include/common.h"
#include "../include/objects.h"
#include "../include/macros.h"
#include "../include/cgiutils.h"
#include "../include/cgiauth.h"
#include "../include/getcgi.h"

static icinga_macros *mac;

extern host *host_list;
extern service *service_list;
extern hostgroup *hostgroup_list;
extern servicegroup *servicegroup_list;
extern contactgroup *contactgroup_list;
extern command *command_list;
extern timeperiod *timeperiod_list;
extern contact *contact_list;
extern servicedependency *servicedependency_list;
extern serviceescalation *serviceescalation_list;
extern hostdependency *hostdependency_list;
extern hostescalation *hostescalation_list;
extern module *module_list;

extern char *action_url_target;
extern char *authorization_config_file;
extern char *authorized_for_all_host_commands;
extern char *authorized_for_all_hosts;
extern char *authorized_for_all_service_commands;
extern char *authorized_for_all_services;
extern char *authorized_for_configuration_information;
extern char *authorized_for_full_command_resolution;
extern char *authorized_for_read_only;
extern char *authorized_for_comments_read_only;
extern char *authorized_for_downtimes_read_only;
extern char *authorized_for_system_commands;
extern char *authorized_for_system_information;
extern char *authorized_contactgroup_for_all_host_commands;
extern char *authorized_contactgroup_for_all_hosts;
extern char *authorized_contactgroup_for_all_service_commands;
extern char *authorized_contactgroup_for_all_services;
extern char *authorized_contactgroup_for_configuration_information;
extern char *authorized_contactgroup_for_full_command_resolution;
extern char *authorized_contactgroup_for_read_only;
extern char *authorized_contactgroup_for_comments_read_only;
extern char *authorized_contactgroup_for_downtimes_read_only;
extern char *authorized_contactgroup_for_system_commands;
extern char *authorized_contactgroup_for_system_information;
extern char cgi_log_archive_path[MAX_FILENAME_LENGTH];
extern char cgi_log_file[MAX_FILENAME_LENGTH];
extern char *csv_data_enclosure;
extern char *csv_delimiter;
extern char *default_user_name;
extern char *host_down_sound;
extern char *host_unreachable_sound;
extern char *http_charset;
extern char *illegal_output_chars;
extern char *macro_user[MAX_USER_MACROS];
extern char main_config_file[MAX_FILENAME_LENGTH];
extern char nagios_check_command[MAX_INPUT_BUFFER];
extern char *normal_sound;
extern char *notes_url_target;
extern char physical_html_path[MAX_FILENAME_LENGTH];
extern char resource_file[MAX_INPUT_BUFFER];
extern char *service_critical_sound;
extern char *service_unknown_sound;
extern char *service_warning_sound;
extern char *splunk_url;
extern char *statusmap_background_image;
extern char url_html_path[MAX_FILENAME_LENGTH];
extern char url_logo_images_path[MAX_FILENAME_LENGTH];
extern char url_stylesheets_path[MAX_FILENAME_LENGTH];

extern int display_header;
extern int content_type;
extern int embedded;
extern int daemon_check;
extern int add_notif_num_hard;
extern int add_notif_num_soft;
extern int color_transparency_index_b;
extern int color_transparency_index_g;
extern int color_transparency_index_r;
extern int cgi_log_rotation_method;
extern int default_downtime_duration;
extern int default_expiring_acknowledgement_duration;
extern int display_status_totals;
extern int default_statusmap_layout_method;
extern int enable_splunk_integration;
extern int enforce_comments_on_actions;
extern int escape_html_tags;
extern int extinfo_show_child_hosts;
extern int highlight_table_rows;
extern int lock_author_names;
extern int lowercase_user_name;
extern int persistent_ack_comments;
extern int refresh_rate;
extern int refresh_type;
extern int result_limit;
extern int show_all_services_host_is_authorized_for;
extern int show_partial_hostgroups;
extern int show_tac_header;
extern int show_tac_header_pending;
extern int showlog_current_states;
extern int showlog_initial_states;
extern int status_show_long_plugin_output;
extern int suppress_maintenance_downtime;
extern int tab_friendly_titles;
extern int tac_show_only_hard_state;
extern int use_authentication;
extern int use_authentication;
extern int use_logging;
extern int use_pending_states;
extern int use_ssl_authentication;
extern int week_starts_on_monday;


int process_cgivars(void);
void display_options(void);
void display_hosts(void);
void display_hostgroups(void);
void display_servicegroups(void);
void display_contacts(void);
void display_contactgroups(void);
void display_services(void);
void display_timeperiods(void);
void display_commands(void);
void display_servicedependencies(void);
void display_serviceescalations(void);
void display_hostdependencies(void);
void display_hostescalations(void);
void display_command_expansion(void);
void display_modules(void);
void display_cgiconfig(void);
void store_default_settings(void);

authdata current_authdata;

int display_type = DISPLAY_NONE;
int get_result_limit = -1;
int result_start = 1;
int total_entries = 0;
int displayed_entries = 0;
char *host_name = NULL;
char *service_desc = NULL;
char to_expand[MAX_COMMAND_BUFFER];
char hashed_color[8];
char *item_name = NULL;					/**< contains exact name user is looking for */
char *search_string = NULL;				/**< contains search string if user searched something */
regex_t search_preg;					/**< contains compiled regex term to use with regexec() */

char *org_action_url_target = "";
char *org_authorization_config_file = "";
char *org_authorized_for_all_host_commands = "";
char *org_authorized_for_all_hosts = "";
char *org_authorized_for_all_service_commands = "";
char *org_authorized_for_all_services = "";
char *org_authorized_for_configuration_information = "";
char *org_authorized_for_full_command_resolution = "";
char *org_authorized_for_read_only = "";
char *org_authorized_for_comments_read_only;
char *org_authorized_for_downtimes_read_only;
char *org_authorized_for_system_commands = "";
char *org_authorized_for_system_information = "";
char *org_authorized_contactgroup_for_all_host_commands = "";
char *org_authorized_contactgroup_for_all_hosts = "";
char *org_authorized_contactgroup_for_all_service_commands = "";
char *org_authorized_contactgroup_for_all_services = "";
char *org_authorized_contactgroup_for_configuration_information = "";
char *org_authorized_contactgroup_for_full_command_resolution = "";
char *org_authorized_contactgroup_for_read_only = "";
char *org_authorized_contactgroup_for_comments_read_only;
char *org_authorized_contactgroup_for_downtimes_read_only;
char *org_authorized_contactgroup_for_system_commands = "";
char *org_authorized_contactgroup_for_system_information = "";
char *org_cgi_log_archive_path = "";
char *org_cgi_log_file = "";
char *org_csv_data_enclosure = "";
char *org_csv_delimiter = "";
char *org_default_user_name = "";
char *org_host_down_sound = "";
char *org_host_unreachable_sound = "";
char *org_http_charset = "";
char *org_illegal_macro_output_chars = "";
char *org_main_config_file = "";
char *org_nagios_check_command = "";
char *org_normal_sound = "";
char *org_notes_url_target = "";
char *org_physical_html_path = "";
char *org_service_critical_sound = "";
char *org_service_unknown_sound = "";
char *org_service_warning_sound = "";
char *org_splunk_url = "";
char *org_statusmap_background_image = "";
char *org_url_html_path = "";
char *org_url_stylesheets_path = "";

int org_add_notif_num_hard;
int org_add_notif_num_soft;
int org_color_transparency_index_b;
int org_color_transparency_index_g;
int org_color_transparency_index_r;
int org_cgi_log_rotation_method;
int org_default_downtime_duration;
int org_default_expiring_acknowledgement_duration;
int org_display_status_totals;
int org_default_statusmap_layout;
int org_enable_splunk_integration;
int org_enforce_comments_on_actions;
int org_escape_html_tags;
int org_extinfo_show_child_hosts;
int org_first_day_of_week;
int org_highlight_table_rows;
int org_lock_author_names;
int org_lowercase_user_name;
int org_persistent_ack_comments;
int org_refresh_rate;
int org_refresh_type;
int org_result_limit;
int org_show_all_services_host_is_authorized_for;
int org_show_partial_hostgroups;
int org_show_tac_header;
int org_show_tac_header_pending;
int org_showlog_current_states;
int org_showlog_initial_states;
int org_status_show_long_plugin_output;
int org_suppress_maintenance_downtime;
int org_tab_friendly_titles;
int org_tac_show_only_hard_state;
int org_use_authentication;
int org_use_authentication;
int org_use_logging;
int org_use_pending_states;
int org_use_ssl_authentication;


int CGI_ID = CONFIG_CGI_ID;

int main(void) {
	int result = OK;
	int regex_i = 0, i = 0;
	int len;
	int saved_escape_html_tags_var = FALSE;
	int search_regex_compile_failed = FALSE;
	char *search_regex = NULL;
	mac = get_global_macros();

	/* get the arguments passed in the URL */
	process_cgivars();

	/* reset internal variables */
	reset_cgi_vars();

	/* store default cgi config vars*/
	store_default_settings();

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

	/* read resource file if possible. if not, ignore error at this time */
	read_icinga_resource_file(resource_file);

	/* initialize macros */
	init_macros();

	/* overwrite config value with amount we got via GET */
	result_limit = (get_result_limit != -1) ? get_result_limit : result_limit;

	/* for json and csv output return all by default */
	if (get_result_limit == -1 && (content_type == JSON_CONTENT || content_type == CSV_CONTENT))
		result_limit = 0;

	document_header(CGI_ID, TRUE, "配置");

	/* get authentication information */
	get_authentication_information(&current_authdata);

	/* see if user tried searching something */
	if (search_string != NULL) {

		/* build regex string */

		/* allocate for 3 extra chars, ^, $ and \0 */
		search_regex = malloc(sizeof(char) * (strlen(search_string) * 2 + 3));
		len = strlen(search_string);
		for (i = 0; i < len; i++, regex_i++) {
			if (search_string[i] == '*') {
				search_regex[regex_i++] = '.';
				search_regex[regex_i] = '*';
			} else
				search_regex[regex_i] = search_string[i];
		}

		search_regex[regex_i] = '\0';

		/* check and compile regex */
		if (regcomp(&search_preg, search_regex, REG_ICASE | REG_NOSUB) != 0)
			search_regex_compile_failed = TRUE;

		/* free regular expression */
		my_free(search_regex);
	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT) {
		/* begin top table */
		printf("<table border=0 width=100%%>\n");
		printf("<tr>\n");

		/* left column of the first row */
		printf("<td align=left valign=top width=33%%>\n");
		display_info_table("配置", &current_authdata, daemon_check);
		printf("</td>\n");

		/* left column of the first row */
		printf("<td align=left width=33%% style='vertical-align:bottom;'>\n");
		printf("<DIV ALIGN=CENTER CLASS='dataTitle'>");

		if (display_type == DISPLAY_HOSTS)			printf("主机");
		else if (display_type == DISPLAY_HOSTGROUPS)		printf("主机组");
		else if (display_type == DISPLAY_SERVICEGROUPS)		printf("服务组");
		else if (display_type == DISPLAY_CONTACTS)		printf("联系人");
		else if (display_type == DISPLAY_CONTACTGROUPS)		printf("联系人组");
		else if (display_type == DISPLAY_SERVICES)		printf("服务");
		else if (display_type == DISPLAY_TIMEPERIODS)		printf("周期");
		else if (display_type == DISPLAY_COMMANDS)		printf("命令");
		else if (display_type == DISPLAY_SERVICEDEPENDENCIES)	printf("服务依赖关系");
		else if (display_type == DISPLAY_SERVICEESCALATIONS)	printf("服务升级");
		else if (display_type == DISPLAY_HOSTDEPENDENCIES)	printf("主机依赖关系");
		else if (display_type == DISPLAY_HOSTESCALATIONS)	printf("主机升级");
		else if (display_type == DISPLAY_MODULES)		printf("模块");
		else if (display_type == DISPLAY_CGICONFIG)		printf("CGI配置设置");

		printf("</DIV>\n");

		if (search_string != NULL || item_name != NULL) {
			saved_escape_html_tags_var = escape_html_tags;
			escape_html_tags = TRUE;

			if (item_name != NULL)
				printf("<DIV align='center'>显示: '%s'</DIV>", html_encode(item_name, FALSE));
			else if (search_regex_compile_failed == FALSE)
				printf("<DIV align='center'>按搜索字符串过滤: '%s'</DIV>", html_encode(search_string, FALSE));
			else
				printf("<div class='errorMessage'>正则表达式'%s'无效!</div>", html_encode(search_string, FALSE));

			escape_html_tags = saved_escape_html_tags_var;
		}

		if (display_type != DISPLAY_NONE && display_type != DISPLAY_ALL && display_type != DISPLAY_COMMAND_EXPANSION && display_type != DISPLAY_CGICONFIG) {
			printf("<div class='page_selector'>\n");
			printf("<div id='page_navigation_copy'></div>");
			page_limit_selector(result_start);
			printf("</div>\n");
		}

		printf("</td>\n");

		/* right hand column of top row */
		printf("<td align=right valign=bottom width=33%%>\n");

		if (display_type != DISPLAY_NONE && is_authorized_for_configuration_information(&current_authdata)) {

			printf("<form method=\"get\" action=\"%s\">\n", CONFIG_CGI);
			printf("<table border=0>\n");

			display_options();

			if (display_type != DISPLAY_COMMAND_EXPANSION && display_type != DISPLAY_CGICONFIG) {
				printf("<tr><td align=left class='reportSelectSubTitle'>搜索 (正则表达式):</td></tr>\n");
				printf("<tr><td align=left class='reportSelectItem'><input type='text' name='search_string' value='%s'></td></tr>\n", (search_string != NULL) ? escape_string(search_string): "");
			}

			printf("<tr><td class='reportSelectItem'><input type='hidden' name='limit' value='%d'><input type='submit' value='更新'></td></tr>\n", result_limit);
			printf("</table>\n");
			printf("</form>\n");

			printf("<div class='csv_export_link'>");
			if (display_type != DISPLAY_COMMAND_EXPANSION) {
				print_export_link(CSV_CONTENT, CONFIG_CGI, NULL);
				print_export_link(JSON_CONTENT, CONFIG_CGI, NULL);
			}
			print_export_link(HTML_CONTENT, CONFIG_CGI, NULL);
			printf("</div>\n");
		}

		/* end of top table */
		printf("</td></tr>\n");
		printf("</table>\n");
	}

	/* empty search string if regex compile failed */
	if (search_regex_compile_failed == TRUE)
		my_free(search_string);


	/* see if user is authorized to view configuration information... */
	if (is_authorized_for_configuration_information(&current_authdata) == FALSE) {
		print_generic_error_message("很显然你没有权限查看您所要求的配置信息...", "如果您认为这是一个错误, 请检查访问CGI的HTTP服务器身份验证要求,并检查您的CGI配置文件的授权选项.", 0);
		document_footer(CGI_ID);
		return OK;
	}


	switch (display_type) {
	case DISPLAY_HOSTS:
		display_hosts();
		break;
	case DISPLAY_HOSTGROUPS:
		display_hostgroups();
		break;
	case DISPLAY_SERVICEGROUPS:
		display_servicegroups();
		break;
	case DISPLAY_CONTACTS:
		display_contacts();
		break;
	case DISPLAY_CONTACTGROUPS:
		display_contactgroups();
		break;
	case DISPLAY_SERVICES:
		display_services();
		break;
	case DISPLAY_TIMEPERIODS:
		display_timeperiods();
		break;
	case DISPLAY_COMMANDS:
		display_commands();
		break;
	case DISPLAY_SERVICEDEPENDENCIES:
		display_servicedependencies();
		break;
	case DISPLAY_SERVICEESCALATIONS:
		display_serviceescalations();
		break;
	case DISPLAY_HOSTDEPENDENCIES:
		display_hostdependencies();
		break;
	case DISPLAY_HOSTESCALATIONS:
		display_hostescalations();
		break;
	case DISPLAY_COMMAND_EXPANSION:
		display_command_expansion();
		break;
	case DISPLAY_MODULES:
		display_modules();
		break;
	case DISPLAY_CGICONFIG:
		display_cgiconfig();
		break;
	case DISPLAY_ALL:
		if (content_type == JSON_CONTENT) {
			display_hosts();
			printf(",\n");
			display_hostgroups();
			printf(",\n");
			display_servicegroups();
			printf(",\n");
			display_contacts();
			printf(",\n");
			display_contactgroups();
			printf(",\n");
			display_services();
			printf(",\n");
			display_timeperiods();
			printf(",\n");
			display_commands();
			printf(",\n");
			display_servicedependencies();
			printf(",\n");
			display_serviceescalations();
			printf(",\n");
			display_hostdependencies();
			printf(",\n");
			display_hostescalations();
			printf(",\n");
			display_modules();
			printf(",\n");
			display_cgiconfig();
			break;
		}
	default:

		if (content_type != CSV_CONTENT && content_type != JSON_CONTENT) {

			printf("<br><br>\n");

			printf("<div align=center class='reportSelectTitle'>选择您想要查看的配置数据类型</div>\n");

			printf("<br><br>\n");

			printf("<form method=\"get\" action=\"%s\">\n", CONFIG_CGI);

			printf("<table border=0 align='center'>\n");

			display_options();

			printf("<tr><td class='reportSelectItem' align='center'><input type='submit' value='继续'></td></tr>\n");
			printf("</table>\n");

			printf("</form>\n");
		}

		break;
	}

	/* regexec search string */
	if (search_string != NULL) {
		regfree(&search_preg);
		my_free(search_string);
	}

	if (item_name != NULL)
		my_free(item_name);

	if (content_type == HTML_CONTENT && display_type != DISPLAY_NONE && display_type != DISPLAY_ALL && display_type != DISPLAY_COMMAND_EXPANSION && display_type != DISPLAY_CGICONFIG)
		page_num_selector(result_start, total_entries, displayed_entries);

	document_footer(CGI_ID);

	return OK;
}

int process_cgivars(void) {
	char **variables;
	int error = FALSE;
	int x;

	variables = getcgivars();
	to_expand[0] = '\0';

	for (x = 0; variables[x] != NULL; x++) {

		/* do some basic length checking on the variable identifier to prevent buffer overflows */
		if (strlen(variables[x]) >= MAX_INPUT_BUFFER - 1) {
			x++;
			continue;
		}

		/* we found the search_string argument */
		else if (!strcmp(variables[x], "search_string")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (strlen(variables[x]) != 0)
				search_string = strdup(variables[x]);
		}

		/* we found the item_name argument */
		else if (!strcmp(variables[x], "item_name")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (strlen(variables[x]) != 0)
				item_name = strdup(variables[x]);
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

		/* we found the configuration type argument */
		else if (!strcmp(variables[x], "type")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			/* what information should we display? */
			if (!strcmp(variables[x], "hosts"))
				display_type = DISPLAY_HOSTS;
			else if (!strcmp(variables[x], "hostgroups"))
				display_type = DISPLAY_HOSTGROUPS;
			else if (!strcmp(variables[x], "servicegroups"))
				display_type = DISPLAY_SERVICEGROUPS;
			else if (!strcmp(variables[x], "contacts"))
				display_type = DISPLAY_CONTACTS;
			else if (!strcmp(variables[x], "contactgroups"))
				display_type = DISPLAY_CONTACTGROUPS;
			else if (!strcmp(variables[x], "services"))
				display_type = DISPLAY_SERVICES;
			else if (!strcmp(variables[x], "timeperiods"))
				display_type = DISPLAY_TIMEPERIODS;
			else if (!strcmp(variables[x], "commands"))
				display_type = DISPLAY_COMMANDS;
			else if (!strcmp(variables[x], "servicedependencies"))
				display_type = DISPLAY_SERVICEDEPENDENCIES;
			else if (!strcmp(variables[x], "serviceescalations"))
				display_type = DISPLAY_SERVICEESCALATIONS;
			else if (!strcmp(variables[x], "hostdependencies"))
				display_type = DISPLAY_HOSTDEPENDENCIES;
			else if (!strcmp(variables[x], "hostescalations"))
				display_type = DISPLAY_HOSTESCALATIONS;
			else if (!strcmp(variables[x], "command"))
				display_type = DISPLAY_COMMAND_EXPANSION;
			else if (!strcmp(variables[x], "modules"))
				display_type = DISPLAY_MODULES;
			else if (!strcmp(variables[x], "cgiconfig"))
				display_type = DISPLAY_CGICONFIG;
			else if (!strcmp(variables[x], "all"))
				display_type = DISPLAY_ALL;

			/* we found the embed option */
			else if (!strcmp(variables[x], "embedded"))
				embedded = TRUE;

			/* we found the nodaemoncheck option */
			else if (!strcmp(variables[x], "nodaemoncheck"))
				daemon_check = FALSE;
		}

		/* we found the string-to-expand argument */
		else if (!strcmp(variables[x], "expand")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}
			strncpy(to_expand, variables[x], MAX_COMMAND_BUFFER);
			to_expand[MAX_COMMAND_BUFFER - 1] = '\0';
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

		/* we received an invalid argument */
		else
			error = TRUE;

	}

	/* free memory allocated to the CGI variables */
	free_cgivars(variables);

	return error;
}

void display_hosts(void) {
	host *temp_host = NULL;
	hostsmember *temp_hostsmember = NULL;
	contactsmember *temp_contactsmember = NULL;
	contactgroupsmember *temp_contactgroupsmember = NULL;
	char *processed_string = NULL;
	int options = 0;
	int odd = 0;
	char time_string[2][16];
	char *bg_class = "";
	int contact = 0;
	int json_start = TRUE;

	if (content_type == JSON_CONTENT) {
		printf("\"主机\": [\n");
	} else if (content_type == CSV_CONTENT) {
		printf("%s主机名称%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s别名/描述%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s显示名称%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s地址%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s地址IPV6%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s上级主机%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s最多. 检查尝试%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s检查间隔%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s重试间隔%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s主机检查命令%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s检查周期%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s强迫%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s启用主动检查%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s启用被动检查%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s检查最新的%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s最新的阙值%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s默认的联系人/组%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s通知时间间隔%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s首次通知延迟%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s通知选项%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s通知周期%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s事件处理%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s启用事件处理%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s跟踪选项%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s启用抖动检测%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s低抖动阙值%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s高抖动阙值%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s抖动检测选项%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s进程性能数据%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s启用故障预测%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s故障预测选项%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s备注%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s备注 URL%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s动作 URL%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s2-D 坐标%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s3-D 坐标%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s状态图图像%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%sVRML图像%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s图标图像%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s图标图像注释%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s保留选项%s",csv_data_enclosure,csv_data_enclosure);
		printf("\n");
	} else {
		printf("<TABLE BORDER=0 CLASS='data'>\n");
		printf("<TR>\n");
		printf("<TH CLASS='data'>主机名称</TH>");
		printf("<TH CLASS='data'>别名/描述</TH>");
		printf("<TH CLASS='data'>显示名称</TH>");
		printf("<TH CLASS='data'>地址</TH>");
		printf("<TH CLASS='data'>地址IPV6</TH>");
		printf("<TH CLASS='data'>上级主机</TH>");
		printf("<TH CLASS='data'>最大.检查尝试</TH>");
		printf("<TH CLASS='data'>检查间隔</TH>\n");
		printf("<TH CLASS='data'>重试间隔</TH>\n");
		printf("<TH CLASS='data'>主机检查命令</TH>");
		printf("<TH CLASS='data'>检查周期</TH>");
		printf("<TH CLASS='data'>强迫</TH>\n");
		printf("<TH CLASS='data'>启用主动检查</TH>\n");
		printf("<TH CLASS='data'>启用被动检查</TH>\n");
		printf("<TH CLASS='data'>检查最新的</TH>\n");
		printf("<TH CLASS='data'>最新的阀值</TH>\n");
		printf("<TH CLASS='data'>默认的联系人/组</TH>\n");
		printf("<TH CLASS='data'>通知间隔</TH>");
		printf("<TH CLASS='data'>首次通知延迟</TH>");
		printf("<TH CLASS='data'>通知选项</TH>");
		printf("<TH CLASS='data'>通知周期</TH>");
		printf("<TH CLASS='data'>事件处理</TH>");
		printf("<TH CLASS='data'>启用事件处理</TH>");
		printf("<TH CLASS='data'>跟踪选项</TH>\n");
		printf("<TH CLASS='data'>启用抖动检测</TH>");
		printf("<TH CLASS='data'>低抖动阈值</TH>");
		printf("<TH CLASS='data'>高抖动阈值</TH>");
		printf("<TH CLASS='data'>抖动检测选项</TH>\n");
		printf("<TH CLASS='data'>进程性能数据</TH>");
		printf("<TH CLASS='data'>启用故障预报</TH>");
		printf("<TH CLASS='data'>故障预测选项</TH>");
		printf("<TH CLASS='data'>备注</TH>");
		printf("<TH CLASS='data'>备注 URL</TH>");
		printf("<TH CLASS='data'>动作 URL</TH>");
		printf("<TH CLASS='data'>2-D 坐标</TH>");
		printf("<TH CLASS='data'>3-D 坐标</TH>");
		printf("<TH CLASS='data'>状态图图像</TH>");
		printf("<TH CLASS='data'>VRML图像</TH>");
		printf("<TH CLASS='data'>图标图像</TH>");
		printf("<TH CLASS='data'>图标图像注释</TH>");
		printf("<TH CLASS='data'>保留选项</TH>");
		printf("</TR>\n");
	}

	/* check all the hosts... */
	for (temp_host = host_list; temp_host != NULL; temp_host = temp_host->next) {

		if (item_name != NULL && strcmp(item_name, temp_host->name) != 0)
			continue;

		/* try to find a match */
		if (search_string != NULL && \
			regexec(&search_preg, temp_host->name, 0, NULL, 0) != 0 && \
		        regexec(&search_preg, temp_host->display_name, 0, NULL, 0) != 0 && \
		        regexec(&search_preg, temp_host->alias, 0, NULL, 0) != 0 && \
		        regexec(&search_preg, temp_host->address, 0, NULL, 0) != 0 && \
		        regexec(&search_preg, temp_host->address6, 0, NULL, 0) != 0)
				continue;

		if (result_limit != 0  && (((total_entries + 1) < result_start) || (total_entries >= ((result_start + result_limit) - 1)))) {
			total_entries++;
			continue;
		}

		displayed_entries++;
		total_entries++;

		/* grab macros */
		grab_host_macros_r(mac, temp_host);

		if (odd) {
			odd = 0;
			bg_class = "dataOdd";
		} else {
			odd = 1;
			bg_class = "dataEven";
		}

		/* print list in json format */
		if (content_type == JSON_CONTENT) {
			// always add a comma, except for the first line
			if (json_start == FALSE)
				printf(",\n");
			json_start = FALSE;
			printf("{ \"主机名称\": \"%s\", ", json_encode(temp_host->name));
			printf("\"别名\": \"%s\", ", json_encode(temp_host->alias));
			printf("\"主机显示名称\": \"%s\", ", json_encode(temp_host->display_name));
			printf("\"地址\": \"%s\", ", temp_host->address);
			printf("\"IPV6地址\": \"%s\", ", temp_host->address6);
			printf("\"上级主机\": [ ");

			/* print list in csv format */
		} else if (content_type == CSV_CONTENT) {
			printf("%s%s%s%s", csv_data_enclosure, temp_host->name, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, temp_host->alias, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, temp_host->display_name, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, temp_host->address, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, temp_host->address6, csv_data_enclosure, csv_delimiter);
			printf("%s", csv_data_enclosure);
		} else {
			printf("<TR CLASS='%s'>\n", bg_class);

			printf("<TD CLASS='%s'><a href='%s?type=services&search_string=%s^%%2E%%2A'>%s</a></TD>\n", bg_class, CONFIG_CGI, url_encode(temp_host->name), html_encode(temp_host->name, FALSE));
			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_host->alias, FALSE));
			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_host->display_name, FALSE));
			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_host->address, FALSE));
			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_host->address6, FALSE));
			printf("<TD CLASS='%s'>", bg_class);
		}

		for (temp_hostsmember = temp_host->parent_hosts; temp_hostsmember != NULL; temp_hostsmember = temp_hostsmember->next) {

			if (temp_hostsmember != temp_host->parent_hosts)
				printf(", ");

			if (content_type == JSON_CONTENT)
				printf("{ \"主机名称\": \"%s\" } ", json_encode(temp_hostsmember->host_name));
			else if (content_type == CSV_CONTENT)
				printf("%s", temp_hostsmember->host_name);
			else
				printf("<a href='%s?type=hosts&item_name=%s'>%s</a>", CONFIG_CGI, url_encode(temp_hostsmember->host_name), html_encode(temp_hostsmember->host_name, FALSE));
		}

		if (temp_host->parent_hosts == NULL)
			printf("%s", (content_type == CSV_CONTENT || content_type == JSON_CONTENT) ? "" : "&nbsp;");

		get_interval_time_string(temp_host->check_interval, time_string[0], sizeof(time_string[0]));
		get_interval_time_string(temp_host->retry_interval, time_string[1], sizeof(time_string[1]));

			if (content_type == JSON_CONTENT) {
				printf("], ");
				printf("\"最大检查尝试\": %d, ",temp_host->max_attempts);
                		printf("\"检查间隔\": \"%s\", ",time_string[0]);
                		printf("\"重试间隔\": \"%s\", ",time_string[1]);

				if (temp_host->host_check_command == NULL)
					printf("\"主机检查命令\":	 null, ");
				else
					printf("\"主机检查命令\": \"%s\", ", json_encode(temp_host->host_check_command));

				if (temp_host->check_period == NULL)
					printf("\"检查周期\":  null, ");
				else
					printf("\"检查周期\": \"%s\", ", json_encode(temp_host->check_period));

				printf("\"强迫\":  %s, ", (temp_host->obsess_over_host == TRUE) ? "true" : "false");
				printf("\"启用主动检查\":  %s, ", (temp_host->checks_enabled == TRUE) ? "true" : "false");
				printf("\"启用被动检查\":  %s, ", (temp_host->accept_passive_host_checks == TRUE) ? "true" : "false");
				printf("\"检查最新的\":  %s, ", (temp_host->check_freshness == TRUE) ? "true" : "false");
				if (temp_host->freshness_threshold == 0)
					printf("\"最新的阀值\":  \"自动检测值\", ");
				else
					printf("\"最新的阀值\": %d, ", temp_host->freshness_threshold);

				printf("\"默认的联系人/组\": [ ");
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s", csv_data_enclosure, csv_delimiter);
				printf("%s%d%s%s", csv_data_enclosure, temp_host->max_attempts, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, time_string[0], csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, time_string[1], csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->host_check_command == NULL) ? "" : temp_host->host_check_command, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->check_period == NULL) ? "" : temp_host->check_period, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->obsess_over_host == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->checks_enabled == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->accept_passive_host_checks == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->check_freshness == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
				if (temp_host->freshness_threshold == 0)
					printf("自动检测值");
				else
					printf("%d", temp_host->freshness_threshold);
				printf("%s%s", csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("</TD>\n");

			printf("<TD CLASS='%s'>%d</TD>\n", bg_class, temp_host->max_attempts);
			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, time_string[0]);
			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, time_string[1]);

			printf("<TD CLASS='%s'>", bg_class);
			if (temp_host->host_check_command == NULL)
				printf("&nbsp;");
			else
				printf("<a href='%s?type=command&host=%s&expand=%s'>%s</a>", CONFIG_CGI, temp_host->name, url_encode(temp_host->host_check_command), html_encode(temp_host->host_check_command, FALSE));
			printf("</TD>\n");

			printf("<TD CLASS='%s'>", bg_class);
			if (temp_host->check_period == NULL)
				printf("&nbsp;");
			else
				printf("<A HREF='%s?type=timeperiods&item_name=%s'>%s</A>", CONFIG_CGI, url_encode(temp_host->check_period), html_encode(temp_host->check_period, FALSE));
			printf("</TD>\n");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_host->obsess_over_host == TRUE) ? "是" : "否");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_host->checks_enabled == TRUE) ? "是" : "否");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_host->accept_passive_host_checks == TRUE) ? "是" : "否");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_host->check_freshness == TRUE) ? "是" : "否");

				printf("<TD CLASS='%s'>", bg_class);
				if (temp_host->freshness_threshold == 0)
					printf("自动检测值");
				else
					printf("%d秒", temp_host->freshness_threshold);
				printf("</TD>\n");

			printf("<TD CLASS='%s'>", bg_class);
		}

		/* find all the contacts for this host... */
		contact = 0;
		for (temp_contactsmember = temp_host->contacts; temp_contactsmember != NULL; temp_contactsmember = temp_contactsmember->next) {
			contact++;
			if (contact > 1)
				printf(", ");

			if (content_type == JSON_CONTENT)
				printf("{ \"联系人名称\": \"%s\" } ", json_encode(temp_contactsmember->contact_name));
			else if (content_type == CSV_CONTENT)
				printf("%s", temp_contactsmember->contact_name);
			else
				printf("<A HREF='%s?type=contacts&item_name=%s'>%s</A>", CONFIG_CGI, url_encode(temp_contactsmember->contact_name), html_encode(temp_contactsmember->contact_name, FALSE));
		}
		for (temp_contactgroupsmember = temp_host->contact_groups; temp_contactgroupsmember != NULL; temp_contactgroupsmember = temp_contactgroupsmember->next) {
			contact++;
			if (contact > 1)
				printf(", ");

			if (content_type == JSON_CONTENT)
				printf("{ \"联系组名称\": \"%s\" } ", json_encode(temp_contactgroupsmember->group_name));
			else if (content_type == CSV_CONTENT)
				printf("%s", temp_contactgroupsmember->group_name);
			else
				printf("<A HREF='%s?type=contactgroups&item_name=%s'>%s</A>", CONFIG_CGI, url_encode(temp_contactgroupsmember->group_name), html_encode(temp_contactgroupsmember->group_name, FALSE));
		}
		if (contact == 0)
			printf("%s", (content_type == CSV_CONTENT || content_type == JSON_CONTENT) ? "" : "&nbsp;");

		get_interval_time_string(temp_host->notification_interval, time_string[0], sizeof(time_string[0]));
		get_interval_time_string(temp_host->first_notification_delay, time_string[1], sizeof(time_string[1]));

			if (content_type == JSON_CONTENT) {
				printf("], ");
				printf("\"通知间隔\": \"%s\", ",time_string[0]);
                printf("\"首次通知延迟\": \"%s\", ",time_string[1]);
                printf("\"通知选项\": [ ");
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, time_string[0], csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, time_string[1], csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("</TD>\n");
				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_host->notification_interval == 0) ? "<i>不重置通知</I>" : html_encode(time_string[0], FALSE));
				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, time_string[1]);
				printf("<TD CLASS='%s'>", bg_class);
			}

			options = 0;
			if (temp_host->notify_on_down == TRUE) {
				options = 1;
				printf("%s宕机%s", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
			}
			if (temp_host->notify_on_unreachable == TRUE) {
				printf("%s%s不可达%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_host->notify_on_recovery == TRUE) {
				printf("%s%s恢复%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_host->notify_on_flapping == TRUE) {
				printf("%s%s抖动%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_host->notify_on_downtime == TRUE) {
				printf("%s%s宕机%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (options == 0 && content_type != JSON_CONTENT)
				printf("无");

			if (content_type == JSON_CONTENT) {
				printf(" ], ");
				if (temp_host->notification_period == NULL)
					printf("\"通知周期\": null, ");
				else
					printf("\"通知周期\": \"%s\", ", json_encode(temp_host->notification_period));

				if (temp_host->event_handler == NULL)
					printf("\"事件处理\": null, ");
				else
					printf("\"事件处理\": \"%s\", ", json_encode(temp_host->event_handler));

				printf("\"启用事件处理\": %s, ", (temp_host->event_handler_enabled == TRUE) ? "true" : "false");
				printf("\"跟踪选项\": [ ");
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->notification_period == NULL) ? "" : temp_host->notification_period, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->event_handler == NULL) ? "" : temp_host->event_handler, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->event_handler_enabled == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("</TD>\n");

			printf("<TD CLASS='%s'>", bg_class);

			if (temp_host->notification_period == NULL)
				printf("&nbsp;");
			else
				printf("<a href='%s?type=timeperiods&irem_name=%s'>%s</a>", CONFIG_CGI, url_encode(temp_host->notification_period), html_encode(temp_host->notification_period, FALSE));
			printf("</TD>\n");

			printf("<TD CLASS='%s'>", bg_class);
			if (temp_host->event_handler == NULL)
				printf("&nbsp");
			else
				/* printf("<a href='%s?type=commands&item_name=%s'>%s</a></TD>\n",CONFIG_CGI,url_encode(strtok(temp_host->event_handler,"!")),html_encode(temp_host->event_handler,FALSE)); */
				printf("<a href='%s?type=command&host=%s&expand=%s'>%s</a>", CONFIG_CGI, temp_host->name, url_encode(temp_host->event_handler), html_encode(temp_host->event_handler, FALSE));

			printf("</TD>\n");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_host->event_handler_enabled == TRUE) ? "是" : "否");

			printf("<TD CLASS='%s'>", bg_class);
		}

			options = 0;
			if (temp_host->stalk_on_up == TRUE) {
				options = 1;
				printf("%s运行%s", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
			}
			if (temp_host->stalk_on_down == TRUE) {
				printf("%s%s宕机%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_host->stalk_on_unreachable == TRUE) {
				printf("%s%s不可达%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (options == 0 && content_type != JSON_CONTENT)
				printf("无");

			if (content_type == JSON_CONTENT) {
				printf(" ], ");
				printf("\"启用抖动检测\": %s, ", (temp_host->flap_detection_enabled == TRUE) ? "true" : "false");
				if (temp_host->low_flap_threshold == 0.0)
					printf("\"低抖动阈值\": \"程序配置值\", ");
				else
					printf("\"低抖动阈值\": %3.1f%%, ", temp_host->low_flap_threshold);

				if (temp_host->high_flap_threshold == 0.0)
					printf("\"高抖动阈值\": \"程序配置值\", ");
				else
					printf("\"高抖动阈值\": %3.1f%%, ", temp_host->high_flap_threshold);

				printf("\"抖动检测选项\": [ ");
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->flap_detection_enabled == TRUE) ? "Yes" : "No", csv_data_enclosure, csv_delimiter);
				if (temp_host->low_flap_threshold == 0.0)
					printf("%s程序配置值%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
				else
					printf("%s%3.1f%%%s%s", csv_data_enclosure, temp_host->low_flap_threshold, csv_data_enclosure, csv_delimiter);
				if (temp_host->high_flap_threshold == 0.0)
					printf("%s程序配置值%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
				else
					printf("%s%3.1f%%%s%s", csv_data_enclosure, temp_host->high_flap_threshold, csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("</TD>\n");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_host->flap_detection_enabled == TRUE) ? "是" : "否");

				printf("<TD CLASS='%s'>", bg_class);
				if (temp_host->low_flap_threshold == 0.0)
					printf("程序配置值");
				else
					printf("%3.1f%%", temp_host->low_flap_threshold);
				printf("</TD>\n");

				printf("<TD CLASS='%s'>", bg_class);
				if (temp_host->high_flap_threshold == 0.0)
					printf("程序配置值");
				else
					printf("%3.1f%%", temp_host->high_flap_threshold);
				printf("</TD>\n");

			printf("<TD CLASS='%s'>", bg_class);
		}

			options = 0;
			if (temp_host->flap_detection_on_up == TRUE) {
				options = 1;
				printf("%s运行%s", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
			}
			if (temp_host->flap_detection_on_down == TRUE) {
				printf("%s%s宕机%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_host->flap_detection_on_unreachable == TRUE) {
				printf("%s%s不可达%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (options == 0 && content_type != JSON_CONTENT)
				printf("无");

			if (content_type == JSON_CONTENT) {
				printf(" ], ");
				printf("\"进程性能数据\": %s, ",(temp_host->process_performance_data==TRUE)?"true":"false");
                printf("\"启用故障预报\": %s, ",(temp_host->failure_prediction_enabled==TRUE)?"true":"false");
                if (temp_host->failure_prediction_options==NULL)
                    printf("\"故障预测选项\": null, ");
                else
                    printf("\"故障预测选项\": \"%s\", ",temp_host->failure_prediction_options);
                if (temp_host->notes==NULL)
                    printf("\"备注\": null, ");
                else
                    printf("\"备注\": \"%s\", ",json_encode(temp_host->notes));
                if (temp_host->notes_url==NULL)
                    printf("\"备注URL\": null, ");
                else
                    printf("\"notes_url\": \"%s\", ",json_encode(temp_host->notes_url));
                if (temp_host->action_url==NULL)
                    printf("\"动作URL\": null, ");
                else
                    printf("\"action_url\": \"%s\", ",json_encode(temp_host->action_url));
                if (temp_host->have_2d_coords==FALSE)
                    printf("\"2-D 坐标\": null, ");
                else
                    printf("\"2-D 坐标\": \"%d,%d\", ",temp_host->x_2d,temp_host->y_2d);
                if (temp_host->have_3d_coords==FALSE)
                    printf("\"3-D 坐标\": null, ");
                else
                    printf("\"3-D 坐标\": \"%.2f,%.2f,%.2f\", ",temp_host->x_3d,temp_host->y_3d,temp_host->z_3d);
                if (temp_host->statusmap_image==NULL)
                    printf("\"状态图图像\": null, ");
                else
                    printf("\"状态图图像\": \"%s\", ",temp_host->statusmap_image);
                if (temp_host->vrml_image==NULL)
                    printf("\"VRML图像\": null, ");
                else
                    printf("\"VRML图像\": \"%s\", ",json_encode(temp_host->vrml_image));
                if (temp_host->icon_image==NULL)
                    printf("\"图标图像\": null, ");
                else
                    printf("\"图标图像\": \"%s\", ",json_encode(temp_host->icon_image));
                if (temp_host->icon_image_alt==NULL)
                    printf("\"图标图像注释\": null, ");
                else
                    printf("\"图标图像注释\": \"%s\", ",json_encode(temp_host->icon_image_alt));
                printf("\"保留选项\": [ ");
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->process_performance_data == TRUE) ? "Yes" : "No", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->failure_prediction_enabled == TRUE) ? "Yes" : "No", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->failure_prediction_options == NULL) ? "" : temp_host->failure_prediction_options, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->notes == NULL) ? "" : temp_host->notes, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->notes_url == NULL) ? "" : temp_host->notes_url, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->action_url == NULL) ? "" : temp_host->action_url, csv_data_enclosure, csv_delimiter);
				if (temp_host->have_2d_coords == FALSE)
					printf("%s%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
				else
					printf("%s%d,%d%s%s", csv_data_enclosure, temp_host->x_2d, temp_host->y_2d, csv_data_enclosure, csv_delimiter);
				if (temp_host->have_3d_coords == FALSE)
					printf("%s%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
				else
					printf("%s%.2f,%.2f,%.2f%s%s", csv_data_enclosure, temp_host->x_3d, temp_host->y_3d, temp_host->z_3d, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->statusmap_image == NULL) ? "" : temp_host->statusmap_image, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->vrml_image == NULL) ? "" : temp_host->vrml_image, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->icon_image == NULL) ? "" : temp_host->icon_image, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_host->icon_image_alt == NULL) ? "" : temp_host->icon_image_alt, csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("</TD>\n");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_host->process_performance_data == TRUE) ? "是" : "否");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_host->failure_prediction_enabled == TRUE) ? "是" : "否");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_host->failure_prediction_options == NULL) ? "&nbsp;" : html_encode(temp_host->failure_prediction_options, FALSE));

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_host->notes == NULL) ? "&nbsp;" : html_encode(temp_host->notes, FALSE));

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_host->notes_url == NULL) ? "&nbsp;" : html_encode(temp_host->notes_url, FALSE));

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_host->action_url == NULL) ? "&nbsp;" : html_encode(temp_host->action_url, FALSE));

			if (temp_host->have_2d_coords == FALSE)
				printf("<TD CLASS='%s'>&nbsp;</TD>\n", bg_class);
			else
				printf("<TD CLASS='%s'>%d,%d</TD>\n", bg_class, temp_host->x_2d, temp_host->y_2d);

			if (temp_host->have_3d_coords == FALSE)
				printf("<TD CLASS='%s'>&nbsp;</TD>\n", bg_class);
			else
				printf("<TD CLASS='%s'>%.2f,%.2f,%.2f</TD>\n", bg_class, temp_host->x_3d, temp_host->y_3d, temp_host->z_3d);

			if (temp_host->statusmap_image == NULL)
				printf("<TD CLASS='%s'>&nbsp;</TD>\n", bg_class);
			else
				printf("<TD CLASS='%s' valign='center'><img src='%s%s' border='0' width='20' height='20'> %s</TD>\n", bg_class, url_logo_images_path, temp_host->statusmap_image, html_encode(temp_host->statusmap_image, FALSE));

			if (temp_host->vrml_image == NULL)
				printf("<TD CLASS='%s'>&nbsp;</TD>\n", bg_class);
			else
				printf("<TD CLASS='%s' valign='center'><img src='%s%s' border='0' width='20' height='20'> %s</TD>\n", bg_class, url_logo_images_path, temp_host->vrml_image, html_encode(temp_host->vrml_image, FALSE));

			if (temp_host->icon_image == NULL)
				printf("<TD CLASS='%s'>&nbsp;</TD>\n", bg_class);
			else {
				process_macros_r(mac, temp_host->icon_image, &processed_string, 0);
				printf("<TD CLASS='%s' valign='center'><img src='%s%s' border='0' width='20' height='20'>%s</TD>\n", bg_class, url_logo_images_path, processed_string, html_encode(temp_host->icon_image, FALSE));
				free(processed_string);
			}

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_host->icon_image_alt == NULL) ? "&nbsp;" : html_encode(temp_host->icon_image_alt, FALSE));

			printf("<TD CLASS='%s'>", bg_class);
		}

			options = 0;
			if (temp_host->retain_status_information == TRUE) {
				options = 1;
				printf("%s状态信息%s", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
			}
			if (temp_host->retain_nonstatus_information == TRUE) {
				printf("%s%s非状态信息%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (options == 0 && content_type != JSON_CONTENT)
				printf("无");

		if (content_type == JSON_CONTENT)
			printf(" ] }");
		else if (content_type == CSV_CONTENT)
			printf("%s\n", csv_data_enclosure);
		else
			printf("</TD>\n</TR>\n");

	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT)
		printf("</TABLE>\n");
	else if (content_type == JSON_CONTENT)
		printf("\n]\n");

	return;
}

void display_hostgroups(void) {
	hostgroup *temp_hostgroup;
	hostsmember *temp_hostsmember;
	int odd = 0;
	int json_start = TRUE;
	char *bg_class = "";

	if (content_type == JSON_CONTENT) {
		printf("\"主机组\": [\n");
	} else if (content_type == CSV_CONTENT) {
		printf("%s组名称%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s描述%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s主机成员%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s备注%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s备注URL%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s动作URL%s\n", csv_data_enclosure, csv_data_enclosure);
	} else {
		printf("<TABLE BORDER=0 CLASS='data'>\n");
		printf("<TR>\n");
		printf("<TH CLASS='data'>组名称</TH>");
		printf("<TH CLASS='data'>描述</TH>");
		printf("<TH CLASS='data'>主机成员</TH>");
		printf("<TH CLASS='data'>备注</TH>");
		printf("<TH CLASS='data'>备注URL</TH>");
		printf("<TH CLASS='data'>动作URL</TH>");
		printf("</TR>\n");
	}

	/* check all the hostgroups... */
	for (temp_hostgroup = hostgroup_list; temp_hostgroup != NULL; temp_hostgroup = temp_hostgroup->next) {

		if (item_name != NULL && strcmp(item_name, temp_hostgroup->group_name) != 0)
			continue;

		/* try to find a match */
		if (search_string != NULL && \
			regexec(&search_preg, temp_hostgroup->group_name, 0, NULL, 0) != 0 && \
		        regexec(&search_preg, temp_hostgroup->alias, 0, NULL, 0) != 0)
				continue;

		if (result_limit != 0  && (((total_entries + 1) < result_start) || (total_entries >= ((result_start + result_limit) - 1)))) {
			total_entries++;
			continue;
		}

		displayed_entries++;
		total_entries++;

		if (odd) {
			odd = 0;
			bg_class = "dataOdd";
		} else {
			odd = 1;
			bg_class = "dataEven";
		}

			/* print list in json format */
			if (content_type == JSON_CONTENT) {
				// always add a comma, except for the first line
				if (json_start == FALSE)
					printf(",\n");
				json_start = FALSE;
				printf("{ \"组名称\": \"%s\", ", json_encode(temp_hostgroup->group_name));
				printf("\"描述\": \"%s\", ", json_encode(temp_hostgroup->alias));
				printf("\"主机组成员\": [");

				/* find all the services that are members of this servicegroup... */
				for (temp_hostsmember = temp_hostgroup->members; temp_hostsmember != NULL; temp_hostsmember = temp_hostsmember->next) {
					if (temp_hostsmember != temp_hostgroup->members)
						printf(",");
					printf(" \"%s\"", json_encode(temp_hostsmember->host_name));
				}
				printf(" ], ");
				if (temp_hostgroup->notes == NULL)
					printf("\"备注\": null, ");
				else
					printf("\"备注\": \"%s\", ", json_encode(temp_hostgroup->notes));
				if (temp_hostgroup->notes_url == NULL)
					printf("\"备注URL\": null, ");
				else
					printf("\"备注URL\": \"%s\", ", json_encode(temp_hostgroup->notes_url));
				if (temp_hostgroup->action_url == NULL)
					printf("\"动作URL\": null }");
				else
					printf("\"动作URL\": \"%s\" }", json_encode(temp_hostgroup->action_url));
				/* print list in csv format */
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s%s%s", csv_data_enclosure, temp_hostgroup->group_name, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, temp_hostgroup->alias, csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);

			/* find all the services that are members of this servicegroup... */
			for (temp_hostsmember = temp_hostgroup->members; temp_hostsmember != NULL; temp_hostsmember = temp_hostsmember->next) {
				if (temp_hostsmember != temp_hostgroup->members)
					printf(", ");
				printf("%s", temp_hostsmember->host_name);
			}

			printf("%s%s", csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_hostgroup->notes == NULL) ? "" : temp_hostgroup->notes, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_hostgroup->notes_url == NULL) ? "" : temp_hostgroup->notes_url, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s\n", csv_data_enclosure, (temp_hostgroup->action_url == NULL) ? "" : temp_hostgroup->action_url, csv_data_enclosure);
		} else {
			printf("<TR CLASS='%s'>\n", bg_class);

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_hostgroup->group_name, FALSE));

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_hostgroup->alias, FALSE));

			printf("<TD CLASS='%s'>", bg_class);

			/* find all the hosts that are members of this hostgroup... */
			for (temp_hostsmember = temp_hostgroup->members; temp_hostsmember != NULL; temp_hostsmember = temp_hostsmember->next) {

				if (temp_hostsmember != temp_hostgroup->members)
					printf(", ");
				printf("<A HREF='%s?type=hosts&item_name=%s'>%s</A>", CONFIG_CGI, url_encode(temp_hostsmember->host_name), html_encode(temp_hostsmember->host_name, FALSE));
			}
			printf("</TD>\n");

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_hostgroup->notes == NULL) ? "&nbsp;" : html_encode(temp_hostgroup->notes, FALSE));

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_hostgroup->notes_url == NULL) ? "&nbsp;" : html_encode(temp_hostgroup->notes_url, FALSE));

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_hostgroup->action_url == NULL) ? "&nbsp;" : html_encode(temp_hostgroup->action_url, FALSE));

			printf("</TR>\n");
		}
	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT)
		printf("</TABLE>\n");
	else if (content_type == JSON_CONTENT)
		printf("\n]\n");

	return;
}

void display_servicegroups(void) {
	servicegroup *temp_servicegroup;
	servicesmember *temp_servicesmember;
	int odd = 0;
	char *bg_class = "";
	int json_start = TRUE;

	if (content_type == JSON_CONTENT) {
		printf("\"服务组\": [\n");
	} else if (content_type == CSV_CONTENT) {
		printf("%s组名称%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s描述%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s服务成员%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s备注%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s备注 URL%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s动作 URL%s", csv_data_enclosure, csv_data_enclosure);
		printf("\n");
	} else {
		printf("<TABLE BORDER=0 CLASS='data'>\n");
		printf("<TR>\n");
		printf("<TH CLASS='data'>组名称</TH>");
		printf("<TH CLASS='data'>描述</TH>");
		printf("<TH CLASS='data'>服务成员</TH>");
		printf("<TH CLASS='data'>备注</TH>");
		printf("<TH CLASS='data'>备注URL</TH>");
		printf("<TH CLASS='data'>动作URL</TH>");
		printf("</TR>\n");
	}

	/* check all the servicegroups... */
	for (temp_servicegroup = servicegroup_list; temp_servicegroup != NULL; temp_servicegroup = temp_servicegroup->next) {

		if (item_name != NULL && strcmp(item_name, temp_servicegroup->group_name) != 0)
			continue;

		/* try to find a match */
		if (search_string != NULL && \
			regexec(&search_preg, temp_servicegroup->group_name, 0, NULL, 0) != 0 && \
		        regexec(&search_preg, temp_servicegroup->alias, 0, NULL, 0) != 0)
				continue;

		if (result_limit != 0  && (((total_entries + 1) < result_start) || (total_entries >= ((result_start + result_limit) - 1)))) {
			total_entries++;
			continue;
		}

		displayed_entries++;
		total_entries++;

		if (odd) {
			odd = 0;
			bg_class = "dataOdd";
		} else {
			odd = 1;
			bg_class = "dataEven";
		}

			/* print list in json format */
			if (content_type == JSON_CONTENT) {
				// always add a comma, except for the first line
				if (json_start == FALSE)
					printf(",\n");
				json_start = FALSE;
				printf("{ \"组名称\": \"%s\", ", json_encode(temp_servicegroup->group_name));
				printf("\"描述\": \"%s\", ", json_encode(temp_servicegroup->alias));
				printf("\"服务组成\": [");

				/* find all the services that are members of this servicegroup... */
				for (temp_servicesmember = temp_servicegroup->members; temp_servicesmember != NULL; temp_servicesmember = temp_servicesmember->next) {
					if (temp_servicesmember != temp_servicegroup->members)
						printf(",");
					printf(" { \"主机名称\": \"%s\", \"服务描述\": \"%s\" }", json_encode(temp_servicesmember->host_name), json_encode(temp_servicesmember->service_description));
				}
				printf(" ], ");
				if (temp_servicegroup->notes == NULL)
					printf("\"备注\": null, ");
				else
					printf("\"备注\": \"%s\", ", json_encode(temp_servicegroup->notes));
				if (temp_servicegroup->notes_url == NULL)
					printf("\"备注 URL\": null, ");
				else
					printf("\"备注 URL\": \"%s\", ", json_encode(temp_servicegroup->notes_url));
				if (temp_servicegroup->action_url == NULL)
					printf("\"动作 URL\": null }");
				else
					printf("\"动作 URL\": \"%s\" }", json_encode(temp_servicegroup->action_url));
				/* print list in csv format */
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s%s%s", csv_data_enclosure, temp_servicegroup->group_name, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, temp_servicegroup->alias, csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);

			/* find all the services that are members of this servicegroup... */
			for (temp_servicesmember = temp_servicegroup->members; temp_servicesmember != NULL; temp_servicesmember = temp_servicesmember->next)
				printf("%s%s / %s", (temp_servicesmember == temp_servicegroup->members) ? "" : ", ", temp_servicesmember->host_name, temp_servicesmember->service_description);

			printf("%s%s", csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_servicegroup->notes == NULL) ? "" : temp_servicegroup->notes, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_servicegroup->notes_url == NULL) ? "" : temp_servicegroup->notes_url, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s\n", csv_data_enclosure, (temp_servicegroup->action_url == NULL) ? "" : temp_servicegroup->action_url, csv_data_enclosure);
		} else {
			printf("<TR CLASS='%s'>\n", bg_class);

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_servicegroup->group_name, FALSE));

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_servicegroup->alias, FALSE));

			printf("<TD CLASS='%s'>", bg_class);

			/* find all the services that are members of this servicegroup... */
			for (temp_servicesmember = temp_servicegroup->members; temp_servicesmember != NULL; temp_servicesmember = temp_servicesmember->next) {

				printf("%s<A HREF='%s?type=hosts&item_name=%s'>%s</A> / ", (temp_servicesmember == temp_servicegroup->members) ? "" : ", ", CONFIG_CGI, url_encode(temp_servicesmember->host_name), html_encode(temp_servicesmember->host_name, FALSE));

				printf("<A HREF='%s?type=services&item_name=%s^", CONFIG_CGI, url_encode(temp_servicesmember->host_name));
				printf("%s'>%s</A>", url_encode(temp_servicesmember->service_description), html_encode(temp_servicesmember->service_description, FALSE));
			}

			printf("</TD>\n");

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_servicegroup->notes == NULL) ? "&nbsp;" : html_encode(temp_servicegroup->notes, FALSE));

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_servicegroup->notes_url == NULL) ? "&nbsp;" : html_encode(temp_servicegroup->notes_url, FALSE));

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_servicegroup->action_url == NULL) ? "&nbsp;" : html_encode(temp_servicegroup->action_url, FALSE));

			printf("</TR>\n");
		}
	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT)
		printf("</TABLE>\n");
	else if (content_type == JSON_CONTENT)
		printf("\n]\n");

	return;
}

void display_contacts(void) {
	contact *temp_contact;
	commandsmember *temp_commandsmember;
	int odd = 0;
	int options;
	int found;
	char *bg_class = "";
	int json_start = TRUE;

	if (content_type == JSON_CONTENT) {
		printf("\"contacts\": [\n");
	} else if (content_type == CSV_CONTENT) {
		printf("%s联系人名称%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s别名%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s电子邮件地址%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s页面地址/数量%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s服务通知选项%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s主机通知选项%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s服务通知周期%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s主机通知周期%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s服务通知命令%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s主机通知命令%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s保留选项%s",csv_data_enclosure,csv_data_enclosure);
		printf("\n");
	} else {
		printf("<TABLE border='0' CLASS='data'>\n");
		printf("<TR>\n");
		printf("<TH CLASS='data'>联系人名称</TH>");
		printf("<TH CLASS='data'>别名</TH>");
		printf("<TH CLASS='data'>电子邮件地址</TH>");
		printf("<TH CLASS='data'>页面地址/数量</TH>");
		printf("<TH CLASS='data'>服务通知选项</TH>");
		printf("<TH CLASS='data'>主机通知选项</TH>");
		printf("<TH CLASS='data'>服务通知周期</TH>");
		printf("<TH CLASS='data'>主机通知周期</TH>");
		printf("<TH CLASS='data'>服务通知命令</TH>");
		printf("<TH CLASS='data'>主机通知命令</TH>");
		printf("<TH CLASS='data'>保留选项</TH>");
		printf("</TR>\n");
	}

	/* check all contacts... */
	for (temp_contact = contact_list; temp_contact != NULL; temp_contact = temp_contact->next) {

		if (item_name != NULL && strcmp(item_name, temp_contact->name) != 0)
			continue;

		/* try to find a match */
		if (search_string != NULL && \
			regexec(&search_preg, temp_contact->name, 0, NULL, 0) != 0 && \
			regexec(&search_preg, temp_contact->alias, 0, NULL, 0) != 0 && \
		        regexec(&search_preg, temp_contact->email, 0, NULL, 0) != 0)
				continue;

		if (result_limit != 0  && (((total_entries + 1) < result_start) || (total_entries >= ((result_start + result_limit) - 1)))) {
			total_entries++;
			continue;
		}

		displayed_entries++;
		total_entries++;

		if (odd) {
			odd = 0;
			bg_class = "dataOdd";
		} else {
			odd = 1;
			bg_class = "dataEven";
		}

		/* print list in json format */
		if (content_type == JSON_CONTENT) {
			// always add a comma, except for the first line
			if (json_start == FALSE)
				printf(",\n");
			json_start = FALSE;

				printf("{ \"联系人名称\": \"%s\", ", json_encode(temp_contact->name));
				printf("\"alias\": \"%s\", ", json_encode(temp_contact->alias));
				if (temp_contact->email == NULL)
					printf("\"电子邮件地址\": null, ");
				else
					printf("\"电子邮件地址\": \"%s\", ", json_encode(temp_contact->email));
				if (temp_contact->pager == NULL)
					printf("\"页面数量\": null, ");
				else
					printf("\"页面数量\": \"%s\", ", json_encode(temp_contact->pager));
				printf("\"服务通知选项\": [");
				/* print list in csv format */
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s%s%s", csv_data_enclosure, temp_contact->name, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, temp_contact->alias, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_contact->email == NULL) ? "" : temp_contact->email, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_contact->pager == NULL) ? "" : temp_contact->pager, csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("<TR CLASS='%s'>\n", bg_class);

			printf("<TD CLASS='%s'><A NAME='%s'>%s</a></TD>\n", bg_class, url_encode(temp_contact->name), html_encode(temp_contact->name, FALSE));
			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_contact->alias, FALSE));
			printf("<TD CLASS='%s'><A HREF='mailto:%s'>%s</A></TD>\n", bg_class, (temp_contact->email == NULL) ? "&nbsp;" : url_encode(temp_contact->email), (temp_contact->email == NULL) ? "&nbsp;" : html_encode(temp_contact->email, FALSE));
			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_contact->pager == NULL) ? "&nbsp;" : html_encode(temp_contact->pager, FALSE));

			printf("<TD CLASS='%s'>", bg_class);
		}

			options = 0;
			if (temp_contact->notify_on_service_unknown == TRUE) {
				options = 1;
				printf("%s未知%s", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
			}
			if (temp_contact->notify_on_service_warning == TRUE) {
				printf("%s%s警报%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_contact->notify_on_service_critical == TRUE) {
				printf("%s%s严重%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_contact->notify_on_service_recovery == TRUE) {
				printf("%s%s恢复%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_contact->notify_on_service_flapping == TRUE) {
				printf("%s%s抖动%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_contact->notify_on_service_downtime == TRUE) {
				printf("%s%s宕机%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (options == 0 && content_type != JSON_CONTENT)
				printf("无");

			if (content_type == JSON_CONTENT) {
				printf(" ], ");
				printf("\"主机通知选项\": [");
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s", csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("</TD>\n");
				printf("<TD CLASS='%s'>", bg_class);
			}

			options = 0;
			if (temp_contact->notify_on_host_down == TRUE) {
				options = 1;
				printf("%s宕机%s", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
			}
			if (temp_contact->notify_on_host_unreachable == TRUE) {
				printf("%s%s不可达%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_contact->notify_on_host_recovery == TRUE) {
				printf("%s%s恢复%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_contact->notify_on_host_flapping == TRUE) {
				printf("%s%s抖动%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_contact->notify_on_host_downtime == TRUE) {
				printf("%s%s宕机%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (options == 0 && content_type != JSON_CONTENT)
				printf("无");

			if (content_type == JSON_CONTENT) {
				printf(" ], ");
				if (temp_contact->service_notification_period == NULL)
					printf("\"服务通知周期\": null, ");
				else
					printf("\"服务通知周期\": \"%s\", ", json_encode(temp_contact->service_notification_period));
				if (temp_contact->host_notification_period == NULL)
					printf("\"主机通知周期\": null, ");
				else
					printf("\"主机通知周期\": \"%s\", ", json_encode(temp_contact->host_notification_period));
				printf("\"服务通知命令\": [ ");
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s", csv_data_enclosure, csv_delimiter);

			printf("%s%s%s%s", csv_data_enclosure, (temp_contact->service_notification_period == NULL) ? "" : temp_contact->service_notification_period, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_contact->host_notification_period == NULL) ? "" : temp_contact->host_notification_period, csv_data_enclosure, csv_delimiter);

			printf("%s", csv_data_enclosure);
		} else {
			printf("</TD>\n");
			printf("<TD CLASS='%s'>", bg_class);

			if (temp_contact->service_notification_period == NULL)
				printf("&nbsp;");
			else
				printf("<A HREF='%s?type=timeperiods&item_name=%s'>%s</A>", CONFIG_CGI, url_encode(temp_contact->service_notification_period), html_encode(temp_contact->service_notification_period, FALSE));
			printf("</TD>\n");

			printf("<TD CLASS='%s'>\n", bg_class);
			if (temp_contact->host_notification_period == NULL)
				printf("&nbsp;");
			else
				printf("<A HREF='%s?type=timeperiods&item_name=%s'>%s</A>", CONFIG_CGI, url_encode(temp_contact->host_notification_period), html_encode(temp_contact->host_notification_period, FALSE));
			printf("</TD>\n");

			printf("<TD CLASS='%s'>", bg_class);
		}

		found = FALSE;
		for (temp_commandsmember = temp_contact->service_notification_commands; temp_commandsmember != NULL; temp_commandsmember = temp_commandsmember->next) {

			if (temp_commandsmember != temp_contact->service_notification_commands)
				printf(", ");

			if (content_type == JSON_CONTENT) {
				printf("\"%s\"", json_encode(temp_commandsmember->command));
			} else if (content_type == CSV_CONTENT) {
				printf("%s", temp_commandsmember->command);
			} else {
				printf("<A HREF='%s?type=command&expand=%s'>%s</A>", CONFIG_CGI, url_encode(temp_commandsmember->command), html_encode(temp_commandsmember->command, FALSE));
			}

			found = TRUE;
		}

			if (found == FALSE && content_type != JSON_CONTENT)
				printf("无");

			if (content_type == JSON_CONTENT) {
				printf(" ], ");
				printf("\"主机通知命令\": [ ");
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s", csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("</TD>\n");
				printf("<TD CLASS='%s'>", bg_class);
			}

		found = FALSE;
		for (temp_commandsmember = temp_contact->host_notification_commands; temp_commandsmember != NULL; temp_commandsmember = temp_commandsmember->next) {

			if (temp_commandsmember != temp_contact->host_notification_commands)
				printf(", ");

			if (content_type == JSON_CONTENT) {
				printf("\"%s\"", json_encode(temp_commandsmember->command));
			} else if (content_type == CSV_CONTENT) {
				printf("%s", temp_commandsmember->command);
			} else {
				printf("<A HREF='%s?type=command&expand=%s'>%s</A>", CONFIG_CGI, url_encode(temp_commandsmember->command), html_encode(temp_commandsmember->command, FALSE));
			}

				found = TRUE;
			}
			if (found == FALSE && content_type != JSON_CONTENT)
				printf("无");

			if (content_type == JSON_CONTENT) {
				printf(" ], ");
				printf("\"保留选项\": [ ");
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s", csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("</TD>\n");
				printf("<TD CLASS='%s'>", bg_class);
			}

			options = 0;
			if (temp_contact->retain_status_information == TRUE) {
				options = 1;
				printf("%s状态信息%s", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
			}
			if (temp_contact->retain_nonstatus_information == TRUE) {
				printf("%s%s非状态信息%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (options == 0 && content_type != JSON_CONTENT)
				printf("无");

		if (content_type == JSON_CONTENT)
			printf(" ] }");
		else if (content_type == CSV_CONTENT)
			printf("%s\n", csv_data_enclosure);
		else
			printf("</TD>\n</TR>\n");
	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT)
		printf("</TABLE>\n");
	else if (content_type == JSON_CONTENT)
		printf("\n]\n");

	return;
}

void display_contactgroups(void) {
	contactgroup *temp_contactgroup;
	contactsmember *temp_contactsmember;
	int odd = 0;
	char *bg_class;
	int json_start = TRUE;

	if (content_type == JSON_CONTENT) {
		printf("\"联系人组\": [\n");
	} else if (content_type == CSV_CONTENT) {
		printf("%s组名称%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s描述%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s联系人成员%s", csv_data_enclosure, csv_data_enclosure);
		printf("\n");
	} else {
		printf("<TABLE BORDER=0 class='data'>\n");
		printf("<TR>\n");
		printf("<TH CLASS='data'>组名称</TH>\n");
		printf("<TH CLASS='data'>描述</TH>\n");
		printf("<TH CLASS='data'>联系人成员</TH>\n");
		printf("</TR>\n");
	}

	/* check all the contact groups... */
	for (temp_contactgroup = contactgroup_list; temp_contactgroup != NULL; temp_contactgroup = temp_contactgroup->next) {

		if (item_name != NULL && strcmp(item_name, temp_contactgroup->group_name) != 0)
			continue;

		/* try to find a match */
		if (search_string != NULL && \
			regexec(&search_preg, temp_contactgroup->group_name, 0, NULL, 0) != 0 && \
		        regexec(&search_preg, temp_contactgroup->alias, 0, NULL, 0) != 0)
				continue;

		if (result_limit != 0  && (((total_entries + 1) < result_start) || (total_entries >= ((result_start + result_limit) - 1)))) {
			total_entries++;
			continue;
		}

		displayed_entries++;
		total_entries++;

		if (odd) {
			odd = 0;
			bg_class = "dataOdd";
		} else {
			odd = 1;
			bg_class = "dataEven";
		}

		/* print list in json format */
		if (content_type == JSON_CONTENT) {
			// always add a comma, except for the first line
			if (json_start == FALSE)
				printf(",\n");
			json_start = FALSE;

				printf("{ \"联系人组名称\": \"%s\", ", json_encode(temp_contactgroup->group_name));
				printf("\"别名\": \"%s\", ", json_encode(temp_contactgroup->alias));
				printf("\"联系人组成员\": [");
				for (temp_contactsmember = temp_contactgroup->members; temp_contactsmember != NULL; temp_contactsmember = temp_contactsmember->next) {
					if (temp_contactsmember != temp_contactgroup->members)
						printf(",");

				printf(" \"%s\"", json_encode(temp_contactsmember->contact_name));
			}
			printf(" ] }");
			/* print list in csv format */
		} else if (content_type == CSV_CONTENT) {
			printf("%s%s%s%s", csv_data_enclosure, temp_contactgroup->group_name, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, temp_contactgroup->alias, csv_data_enclosure, csv_delimiter);
			printf("%s", csv_data_enclosure);
			for (temp_contactsmember = temp_contactgroup->members; temp_contactsmember != NULL; temp_contactsmember = temp_contactsmember->next) {
				if (temp_contactsmember != temp_contactgroup->members)
					printf(", ");

				printf("%s", temp_contactsmember->contact_name);
			}
			printf("%s\n", csv_data_enclosure);
		} else {

			printf("<TR CLASS='%s'>\n", bg_class);

			printf("<TD CLASS='%s'><A NAME='%s'></A>%s</TD>\n", bg_class, url_encode(temp_contactgroup->group_name), html_encode(temp_contactgroup->group_name, FALSE));
			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_contactgroup->alias, FALSE));

			/* find all the contact who are members of this contact group... */
			printf("<TD CLASS='%s'>", bg_class);
			for (temp_contactsmember = temp_contactgroup->members; temp_contactsmember != NULL; temp_contactsmember = temp_contactsmember->next) {

				if (temp_contactsmember != temp_contactgroup->members)
					printf(", ");

				printf("<A HREF='%s?type=contacts&item_name=%s'>%s</A>", CONFIG_CGI, url_encode(temp_contactsmember->contact_name), html_encode(temp_contactsmember->contact_name, FALSE));
			}
			printf("</TD>\n");
			printf("</TR>\n");
		}
	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT)
		printf("</TABLE>\n");
	else if (content_type == JSON_CONTENT)
		printf("\n]\n");

	return;
}

void display_services(void) {
	service *temp_service = NULL;
	contactsmember *temp_contactsmember = NULL;
	contactgroupsmember *temp_contactgroupsmember = NULL;
	char *processed_string = NULL;
	char command_line[MAX_INPUT_BUFFER];
	char host_service_name[MAX_INPUT_BUFFER];
	char time_string[2][16];
	char *bg_class;
	int options;
	int odd = 0;
	int contact = 0;
	int json_start = TRUE;

	if (content_type == JSON_CONTENT) {
		printf("\"服务\": [\n");
	} else if (content_type == CSV_CONTENT) {
		printf("%s主机%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s描述%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s显示名称%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s最大.检查尝试%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s常规检查间隔%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s重试间隔%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s检查命令%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s检查周期%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s并行%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s可变的%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s强迫%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s启用主动检查%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s启用被动检查%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s检查最新的%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s最新的阀值%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s默认联系人/组%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s启用通知%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s通知间隔%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s首次通知延迟%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s通知选项%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s通知周期%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s事件处理%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s启用事件处理%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s跟踪选项%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s启用抖动检测%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s低抖动阈值%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s高抖动阈值%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s抖动检测选项%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s进程性能数据%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s启用故障预测%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s失败故障选项%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s备注%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s备注 URL%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s动作 URL%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s图标图像%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s图标图像注释%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s保留选项%s",csv_data_enclosure,csv_data_enclosure);
		printf("\n");
	} else {
		printf("<TABLE BORDER=0 CLASS='data'>\n");
		printf("<TR>\n");
		printf("<TH CLASS='data'>主机</TH>\n");
		printf("<TH CLASS='data'>描述</TH>\n");
		printf("<TH CLASS='data'>显示名称</TH>\n");
		printf("<TH CLASS='data'>最大.检查尝试</TH>\n");
		printf("<TH CLASS='data'>常规检查间隔</TH>\n");
		printf("<TH CLASS='data'>重试间隔</TH>\n");
		printf("<TH CLASS='data'>检查命令</TH>\n");
		printf("<TH CLASS='data'>检查周期</TH>\n");
		printf("<TH CLASS='data'>并行</TH>\n");
		printf("<TH CLASS='data'>可变的</TH>\n");
		printf("<TH CLASS='data'>强迫</TH>\n");
		printf("<TH CLASS='data'>启用主动检查</TH>\n");
		printf("<TH CLASS='data'>启用被动检查</TH>\n");
		printf("<TH CLASS='data'>检查最新的</TH>\n");
		printf("<TH CLASS='data'>最新的阀值</TH>\n");
		printf("<TH CLASS='data'>默认联系人/组</TH>\n");
		printf("<TH CLASS='data'>启用通知</TH>\n");
		printf("<TH CLASS='data'>通知间隔</TH>\n");
		printf("<TH CLASS='data'>首次通知延迟</TH>\n");
		printf("<TH CLASS='data'>通知选项</TH>\n");
		printf("<TH CLASS='data'>通知周期</TH>\n");
		printf("<TH CLASS='data'>事件处理</TH>");
		printf("<TH CLASS='data'>启用事件处理</TH>");
		printf("<TH CLASS='data'>跟踪选项</TH>\n");
		printf("<TH CLASS='data'>启用抖动检测</TH>");
		printf("<TH CLASS='data'>低抖动阈值</TH>");
		printf("<TH CLASS='data'>高抖动阈值</TH>");
		printf("<TH CLASS='data'>抖动检测选项</TH>");
		printf("<TH CLASS='data'>进程性能数据</TH>");
		printf("<TH CLASS='data'>启用故障预测</TH>");
		printf("<TH CLASS='data'>失败预测选项</TH>");
		printf("<TH CLASS='data'>备注</TH>");
		printf("<TH CLASS='data'>备注URL</TH>");
		printf("<TH CLASS='data'>动作URL</TH>");
		printf("<TH CLASS='data'>图标图像</TH>");
		printf("<TH CLASS='data'>图标图像注释</TH>");
		printf("<TH CLASS='data'>保留选项</TH>");
		printf("</TR>\n");
	}

	/* check all the services... */
	for (temp_service = service_list; temp_service != NULL; temp_service = temp_service->next) {

		/* try to match on combination of host name and service description */
		snprintf(host_service_name, sizeof(host_service_name), "%s^%s", temp_service->host_name, temp_service->description);
		host_service_name[sizeof(host_service_name) - 1] = '\x0';

		if (item_name != NULL && strcmp(item_name, host_service_name) != 0)
			continue;

		/* try to find a match */
		if (search_string != NULL && \
			regexec(&search_preg, temp_service->description, 0, NULL, 0) != 0 && \
			regexec(&search_preg, temp_service->display_name, 0, NULL, 0) != 0 && \
			regexec(&search_preg, temp_service->host_name, 0, NULL, 0) != 0 && \
		        regexec(&search_preg, host_service_name, 0, NULL, 0) != 0)
				continue;

		if (result_limit != 0  && (((total_entries + 1) < result_start) || (total_entries >= ((result_start + result_limit) - 1)))) {
			total_entries++;
			continue;
		}

		displayed_entries++;
		total_entries++;

		/* grab macros */
		grab_service_macros_r(mac, temp_service);

		if (odd) {
			odd = 0;
			bg_class = "dataOdd";
		} else {
			odd = 1;
			bg_class = "dataEven";
		}

		get_interval_time_string(temp_service->check_interval, time_string[0], sizeof(time_string[0]));
		get_interval_time_string(temp_service->retry_interval, time_string[1], sizeof(time_string[1]));
		strncpy(command_line, temp_service->service_check_command, sizeof(command_line));
		command_line[sizeof(command_line) - 1] = '\x0';

		/* print list in json format */
		if (content_type == JSON_CONTENT) {
			// always add a comma, except for the first line
			if (json_start == FALSE)
				printf(",\n");
			json_start = FALSE;
			printf("{ \"主机名称\": \"%s\", ", json_encode(temp_service->host_name));
			printf("\"服务描述\": \"%s\", ", json_encode(temp_service->description));
			printf("\"服务显示名称\": \"%s\", ", json_encode(temp_service->display_name));
			printf("\"最大检查尝试\": %d, ", temp_service->max_attempts);
			printf("\"常规检查间隔\": \"%s\", ", time_string[0]);
			printf("\"重试间隔\": \"%s\", ", time_string[1]);
			printf("\"检查命令\": \"%s\", ", json_encode(command_line));
			if (temp_service->check_period == NULL)
				printf("\"检查周期\": null, ");
			else
				printf("\"检查周期\": \"%s\", ", json_encode(temp_service->check_period));

				printf("\"并行\": %s, ", (temp_service->parallelize == TRUE) ? "true" : "false");
				printf("\"可变的\": %s, ", (temp_service->is_volatile == TRUE) ? "true" : "false");
				printf("\"强迫\": %s, ", (temp_service->obsess_over_service == TRUE) ? "true" : "false");
				printf("\"启用主动检查\": %s, ", (temp_service->checks_enabled == TRUE) ? "true" : "false");
				printf("\"启用被动检查\": %s, ", (temp_service->accept_passive_service_checks == TRUE) ? "true" : "false");
				printf("\"检查最新的\": %s, ", (temp_service->check_freshness == TRUE) ? "true" : "false");
				if (temp_service->freshness_threshold == 0)
					printf("\"最新的阀值\":  \"自动检测值\", ");
				else
					printf("\"最新的阀值\":  %d, ", temp_service->freshness_threshold);

				printf("\"默认联系人/组\": [ ");

			/* print list in csv format */
		} else if (content_type == CSV_CONTENT) {
			printf("%s%s%s%s", csv_data_enclosure, temp_service->host_name, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, temp_service->description, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, temp_service->display_name, csv_data_enclosure, csv_delimiter);
			printf("%s%d%s%s", csv_data_enclosure, temp_service->max_attempts, csv_data_enclosure, csv_delimiter);

			printf("%s%s%s%s", csv_data_enclosure, time_string[0], csv_data_enclosure, csv_delimiter);

			printf("%s%s%s%s", csv_data_enclosure, time_string[1], csv_data_enclosure, csv_delimiter);

			printf("%s%s%s%s", csv_data_enclosure, command_line, csv_data_enclosure, csv_delimiter);

				printf("%s%s%s%s", csv_data_enclosure, (temp_service->check_period == NULL) ? "" : temp_service->check_period, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_service->parallelize == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_service->is_volatile == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_service->obsess_over_service == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_service->checks_enabled == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_service->accept_passive_service_checks == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_service->check_freshness == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);

				printf("%s", csv_data_enclosure);
				if (temp_service->freshness_threshold == 0)
					printf("自动检测值");
				else
					printf("%d", temp_service->freshness_threshold);

			printf("%s%s", csv_data_enclosure, csv_delimiter);

			printf("%s", csv_data_enclosure);

		} else {

			printf("<TR CLASS='%s'>\n", bg_class);

			printf("<TD CLASS='%s'><A NAME='%s;", bg_class, url_encode(temp_service->host_name));
			printf("%s'></A>", url_encode(temp_service->description));
			printf("<A HREF='%s?type=hosts&item_name=%s'>%s</A></TD>\n", CONFIG_CGI, url_encode(temp_service->host_name), html_encode(temp_service->host_name, FALSE));

			/* find a way to show display_name if set once */
			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_service->description, FALSE));

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_service->display_name, FALSE));

			printf("<TD CLASS='%s'>%d</TD>\n", bg_class, temp_service->max_attempts);

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, time_string[0]);

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, time_string[1]);

			printf("<TD CLASS='%s'><A HREF='%s?type=command&host=%s&service=%s&expand=%s'>%s</A></TD>\n", bg_class, CONFIG_CGI, temp_service->host_name, temp_service->description, url_encode(command_line), html_encode(command_line, FALSE));

			printf("<TD CLASS='%s'>", bg_class);
			if (temp_service->check_period == NULL)
				printf("&nbsp;");
			else
				printf("<A HREF='%s?type=timeperiods&item_name=%s'>%s</A>", CONFIG_CGI, url_encode(temp_service->check_period), html_encode(temp_service->check_period, FALSE));
			printf("</TD>\n");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_service->parallelize == TRUE) ? "是" : "否");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_service->is_volatile != FALSE) ? "是" : "否");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_service->obsess_over_service == TRUE) ? "是" : "否");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_service->checks_enabled == TRUE) ? "是" : "否");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_service->accept_passive_service_checks == TRUE) ? "是" : "否");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_service->check_freshness == TRUE) ? "是" : "否");

				printf("<TD CLASS='%s'>", bg_class);
				if (temp_service->freshness_threshold == 0)
					printf("自动检测值");
				else
					printf("%d seconds", temp_service->freshness_threshold);
				printf("</TD>\n");

			printf("<TD CLASS='%s'>", bg_class);
		}

		contact = 0;
		for (temp_contactsmember = temp_service->contacts; temp_contactsmember != NULL; temp_contactsmember = temp_contactsmember->next) {
			contact++;
			if (contact > 1)
				printf(", ");

			if (content_type == JSON_CONTENT)
				printf("{ \"联系人名称\": \"%s\" } ", json_encode(temp_contactsmember->contact_name));
			else if (content_type == CSV_CONTENT)
				printf("%s", temp_contactsmember->contact_name);
			else
				printf("<A HREF='%s?type=contacts&item_name=%s'>%s</A>", CONFIG_CGI, url_encode(temp_contactsmember->contact_name), html_encode(temp_contactsmember->contact_name, FALSE));
		}

		for (temp_contactgroupsmember = temp_service->contact_groups; temp_contactgroupsmember != NULL; temp_contactgroupsmember = temp_contactgroupsmember->next) {
			contact++;
			if (contact > 1)
				printf(", ");

			if (content_type == JSON_CONTENT)
				printf("{ \"联系人组名称\": \"%s\" } ", json_encode(temp_contactgroupsmember->group_name));
			else if (content_type == CSV_CONTENT)
				printf("%s", temp_contactgroupsmember->group_name);
			else
				printf("<A HREF='%s?type=contactgroups&item_name=%s'>%s</A>", CONFIG_CGI, url_encode(temp_contactgroupsmember->group_name), html_encode(temp_contactgroupsmember->group_name, FALSE));
		}
		if (contact == 0)
			printf("%s", (content_type == CSV_CONTENT || content_type == JSON_CONTENT) ? "" : "&nbsp;");

		get_interval_time_string(temp_service->notification_interval, time_string[0], sizeof(time_string[0]));
		get_interval_time_string(temp_service->first_notification_delay, time_string[1], sizeof(time_string[1]));

			if (content_type == JSON_CONTENT) {
				printf("], ");
				printf("\"启用通知\": %s, ", (temp_service->notifications_enabled == TRUE) ? "true" : "false");
				printf("\"通知间隔\": \"%s\", ", time_string[0]);
				printf("\"首次通知延迟\": \"%s\", ", time_string[1]);
				printf("\"知选项\": [ ");
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_service->notifications_enabled == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_service->notification_interval == 0) ? "不重置通知" : time_string[0], csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, time_string[1], csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("</TD>\n");
				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_service->notifications_enabled == TRUE) ? "是" : "否");
				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_service->notification_interval == 0) ? "<i>不重置通知</i>" : html_encode(time_string[0], FALSE));
				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, time_string[1]);
				printf("<TD CLASS='%s'>", bg_class);
			}

			options = 0;
			if (temp_service->notify_on_unknown == TRUE) {
				options = 1;
				printf("%s未知%s", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
			}
			if (temp_service->notify_on_warning == TRUE) {
				printf("%s%s警报%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_service->notify_on_critical == TRUE) {
				printf("%s%s严重%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_service->notify_on_recovery == TRUE) {
				printf("%s%s恢复%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_service->notify_on_flapping == TRUE) {
				printf("%s%s抖动%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_service->notify_on_downtime == TRUE) {
				printf("%s%s宕机%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (options == 0 && content_type != JSON_CONTENT)
				printf("无");

			if (content_type == JSON_CONTENT) {
				printf(" ], ");
				if (temp_service->notification_period == NULL)
					printf("\"通知周期\": null, ");
				else
					printf("\"通知周期\": \"%s\", ", json_encode(temp_service->notification_period));

				if (temp_service->event_handler == NULL)
					printf("\"事件处理\": null, ");
				else
					printf("\"事件处理\": \"%s\", ", json_encode(temp_service->event_handler));

			printf("\"启用事件处理\": %s, ", (temp_service->event_handler_enabled == TRUE) ? "true" : "false");
			printf("\"跟踪选项\": [ ");
		} else if (content_type == CSV_CONTENT) {
			printf("%s%s", csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_service->notification_period == NULL) ? "" : temp_service->notification_period, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_service->event_handler == NULL) ? "" : temp_service->event_handler, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_service->event_handler_enabled == TRUE) ? "Yes" : "No", csv_data_enclosure, csv_delimiter);
			printf("%s", csv_data_enclosure);
		} else {
			printf("</TD>\n");
			printf("<TD CLASS='%s'>", bg_class);
			if (temp_service->notification_period == NULL)
				printf("&nbsp;");
			else
				printf("<A HREF='%s?type=timeperiods&item_name=%s'>%s</A>", CONFIG_CGI, url_encode(temp_service->notification_period), html_encode(temp_service->notification_period, FALSE));
			printf("</TD>\n");
			printf("<TD CLASS='%s'>", bg_class);
			if (temp_service->event_handler == NULL)
				printf("&nbsp;");
			else
				printf("<A HREF='%s?type=command&host=%s&service=%s&expand=%s'>%s</A>", CONFIG_CGI, temp_service->host_name, temp_service->description, url_encode(temp_service->event_handler), html_encode(temp_service->event_handler, FALSE));
			printf("</TD>\n");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_service->event_handler_enabled == TRUE) ? "是" : "否");

			printf("<TD CLASS='%s'>", bg_class);
		}

			options = 0;
			if (temp_service->stalk_on_ok == TRUE) {
				options = 1;
				printf("%s正常%s", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				printf("正常");
			}
			if (temp_service->stalk_on_warning == TRUE) {
				printf("%s%s警报%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_service->stalk_on_unknown == TRUE) {
				printf("%s%s未知%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_service->stalk_on_critical == TRUE) {
				printf("%s%s严重%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (options == 0 && content_type != JSON_CONTENT)
				printf("无");

			if (content_type == JSON_CONTENT) {
				printf(" ], ");
				printf("\"启用抖动检测\": %s, ", (temp_service->flap_detection_enabled == TRUE) ? "true" : "false");
				if (temp_service->low_flap_threshold == 0.0)
					printf("\"低抖动阈值\": \"程序配置值\", ");
				else
					printf("\"低抖动阈值\": %3.1f%%, ", temp_service->low_flap_threshold);

				if (temp_service->high_flap_threshold == 0.0)
					printf("\"高抖动阈值\": \"程序配置值\", ");
				else
					printf("\"高抖动阈值\": %3.1f%%, ", temp_service->high_flap_threshold);

				printf("\"抖动检测选项\": [ ");
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s", csv_data_enclosure, csv_delimiter);

				printf("%s%s%s%s", csv_data_enclosure, (temp_service->flap_detection_enabled == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);

				printf("%s", csv_data_enclosure);
				if (temp_service->low_flap_threshold == 0.0)
					printf("程序配置值");
				else
					printf("%3.1f%%", temp_service->low_flap_threshold);

			printf("%s%s", csv_data_enclosure, csv_delimiter);

				printf("%s", csv_data_enclosure);
				if (temp_service->high_flap_threshold == 0.0)
					printf("程序配置值");
				else
					printf("%3.1f%%", temp_service->high_flap_threshold);

			printf("%s%s", csv_data_enclosure, csv_delimiter);

			printf("%s", csv_data_enclosure);
		} else {
			printf("</TD>\n");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_service->flap_detection_enabled == TRUE) ? "是" : "否");

				printf("<TD CLASS='%s'>", bg_class);
				if (temp_service->low_flap_threshold == 0.0)
					printf("程序配置值");
				else
					printf("%3.1f%%", temp_service->low_flap_threshold);
				printf("</TD>\n");

				printf("<TD CLASS='%s'>", bg_class);
				if (temp_service->high_flap_threshold == 0.0)
					printf("程序配置值");
				else
					printf("%3.1f%%", temp_service->high_flap_threshold);
				printf("</TD>\n");

			printf("<TD CLASS='%s'>", bg_class);
		}

			options = 0;
			if (temp_service->flap_detection_on_ok == TRUE) {
				options = 1;
				printf("%s正常%s", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
			}
			if (temp_service->flap_detection_on_warning == TRUE) {
				printf("%s%s警报%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_service->flap_detection_on_unknown == TRUE) {
				printf("%s%s未知n%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_service->flap_detection_on_critical == TRUE) {
				printf("%s%s严重%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (options == 0 && content_type != JSON_CONTENT)
				printf("无");

			if (content_type == JSON_CONTENT) {
				printf(" ], ");
				printf("\"进程性能数\": %s, ", (temp_service->process_performance_data == TRUE) ? "true" : "false");
				printf("\"启用故障预测\": %s, ", (temp_service->failure_prediction_enabled == TRUE) ? "true" : "false");
				if (temp_service->failure_prediction_options == NULL)
					printf("\"故障预测选项\": null, ");
				else
					printf("\"故障预测选项\": \"%s\", ", temp_service->failure_prediction_options);
				if (temp_service->notes == NULL)
					printf("\"备注\": null, ");
				else
					printf("\"备注\": \"%s\", ", json_encode(temp_service->notes));
				if (temp_service->notes_url == NULL)
					printf("\"备注 URL\": null, ");
				else
					printf("\"notes备注 URL_url\": \"%s\", ", json_encode(temp_service->notes_url));
				if (temp_service->action_url == NULL)
					printf("\"动作 URL\": null, ");
				else
					printf("\"动作 URL\": \"%s\", ", json_encode(temp_service->action_url));
				if (temp_service->icon_image == NULL)
					printf("\"图标图像\": null, ");
				else {
					process_macros(temp_service->icon_image, &processed_string, 0);
					printf("\"图标图像\": \"%s\", ", json_encode(processed_string));
					free(processed_string);
				}
				if (temp_service->icon_image_alt == NULL)
					printf("\"图标图像注释\": null, ");
				else
					printf("\"图标图像注释\": \"%s\", ", json_encode(temp_service->icon_image_alt));
				printf("\"保留选项\": [ ");
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s", csv_data_enclosure, csv_delimiter);

				printf("%s%s%s%s", csv_data_enclosure, (temp_service->process_performance_data == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);

				printf("%s%s%s%s", csv_data_enclosure, (temp_service->failure_prediction_enabled == TRUE) ? "是" : "否", csv_data_enclosure, csv_delimiter);

			printf("%s%s%s%s", csv_data_enclosure, (temp_service->failure_prediction_options == NULL) ? "" : temp_service->failure_prediction_options, csv_data_enclosure, csv_delimiter);

			printf("%s%s%s%s", csv_data_enclosure, (temp_service->notes == NULL) ? "" : temp_service->notes, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_service->notes_url == NULL) ? "" : temp_service->notes_url, csv_data_enclosure, csv_delimiter);
			printf("%s%s%s%s", csv_data_enclosure, (temp_service->action_url == NULL) ? "" : temp_service->action_url, csv_data_enclosure, csv_delimiter);

			printf("%s", csv_data_enclosure);
			if (temp_service->icon_image != NULL) {
				process_macros(temp_service->icon_image, &processed_string, 0);
				printf("%s", processed_string);
				free(processed_string);
			}
			printf("%s%s", csv_data_enclosure, csv_delimiter);

			printf("%s%s%s%s", csv_data_enclosure, (temp_service->icon_image_alt == NULL) ? "" : temp_service->icon_image_alt, csv_data_enclosure, csv_delimiter);

			printf("%s", csv_data_enclosure);
		} else {
			printf("</TD>\n");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_service->process_performance_data == TRUE) ? "是" : "否");

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_service->failure_prediction_enabled == TRUE) ? "是" : "否");

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_service->failure_prediction_options == NULL) ? "&nbsp;" : html_encode(temp_service->failure_prediction_options, FALSE));

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_service->notes == NULL) ? "&nbsp;" : html_encode(temp_service->notes, FALSE));

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_service->notes_url == NULL) ? "&nbsp;" : html_encode(temp_service->notes_url, FALSE));

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_service->action_url == NULL) ? "&nbsp;" : html_encode(temp_service->action_url, FALSE));

			if (temp_service->icon_image == NULL)
				printf("<TD CLASS='%s'>&nbsp;</TD>\n", bg_class);
			else {
				process_macros(temp_service->icon_image, &processed_string, 0);
				printf("<TD CLASS='%s' valign='center'><img src='%s%s' border='0' width='20' height='20'> %s</TD>\n", bg_class, url_logo_images_path, processed_string, html_encode(temp_service->icon_image, FALSE));
				free(processed_string);
			}

			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_service->icon_image_alt == NULL) ? "&nbsp;" : html_encode(temp_service->icon_image_alt, FALSE));

			printf("<TD CLASS='%s'>", bg_class);
		}

			options = 0;
			if (temp_service->retain_status_information == TRUE) {
				options = 1;
				printf("%s状态信息%s", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
			}
			if (temp_service->retain_nonstatus_information == TRUE) {
				printf("%s%s非状态信息%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (options == 0 && content_type != JSON_CONTENT)
				printf("None");

		if (content_type == JSON_CONTENT) {
			printf(" ] }");
		} else if (content_type == CSV_CONTENT) {
			printf("%s\n", csv_data_enclosure);
		} else {
			printf("</TD>\n");
			printf("</TR>\n");
		}
	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT)
		printf("</TABLE>\n");
	else if (content_type == JSON_CONTENT)
		printf("\n]\n");

	return;
}

void display_timeperiods(void) {
	timerange *temp_timerange = NULL;
	daterange *temp_daterange = NULL;
	timeperiod *temp_timeperiod = NULL;
	timeperiodexclusion *temp_timeperiodexclusion = NULL;
	char *months[12]={"一月","二月","三月","四月","五月","六月","七月","八月","九月","十月","十一月","十二月"};
	char *days[7]={"周日","周一","周二","周三","周四","周五","周六"};
	int odd = 0;
	int day = 0;
	int x = 0;
	char *bg_class = "";
	char timestring[10];
	int hours = 0;
	int minutes = 0;
	int seconds = 0;
	int line = 0;
	int json_start = TRUE;

	if (content_type == JSON_CONTENT) {
		printf("\"时间范围\": [\n");
	} else if (content_type == CSV_CONTENT) {
		printf("%s名称%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s别名/描述%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s不包含%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s天/日期%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s时间%s", csv_data_enclosure, csv_data_enclosure);
		printf("\n");
	} else {
		printf("<TABLE BORDER=0 CLASS='data'>\n");
		printf("<TR>\n");
		printf("<TH CLASS='data'>名称</TH>\n");
		printf("<TH CLASS='data'>别名/描述</TH>\n");
		printf("<TH CLASS='data'>不包含</TH>\n");
		printf("<TH CLASS='data'>天/日期</TH>\n");
		printf("<TH CLASS='data'>时间</TH>\n");
		printf("</TR>\n");
	}

	/* check all the time periods... */
	for (temp_timeperiod = timeperiod_list; temp_timeperiod != NULL; temp_timeperiod = temp_timeperiod->next) {

		if (item_name != NULL && strcmp(item_name, temp_timeperiod->name) != 0)
			continue;

		/* try to find a match */
		if (search_string != NULL && \
			regexec(&search_preg, temp_timeperiod->name, 0, NULL, 0) != 0 && \
		        regexec(&search_preg, temp_timeperiod->alias, 0, NULL, 0) != 0)
				continue;

		if (result_limit != 0  && (((total_entries + 1) < result_start) || (total_entries >= ((result_start + result_limit) - 1)))) {
			total_entries++;
			continue;
		}

		displayed_entries++;
		total_entries++;

		if (odd) {
			odd = 0;
			bg_class = "dataOdd";
		} else {
			odd = 1;
			bg_class = "dataEven";
		}

		/* print list in json format */
		if (content_type == JSON_CONTENT) {
			// always add a comma, except for the first line
			if (json_start == FALSE)
				printf(",\n");
			json_start = FALSE;

				printf("{ \"时间范围名称\": \"%s\", ", json_encode(temp_timeperiod->name));
				printf("\"别名\": \"%s\", ", json_encode(temp_timeperiod->alias));
				printf("\"不包含\": [ ");
				/* print list in csv format */
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s%s%s", csv_data_enclosure, temp_timeperiod->name, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, temp_timeperiod->alias, csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("<TR CLASS='%s'>\n", bg_class);

			printf("<TD CLASS='%s'><A NAME='%s'>%s</A></TD>\n", bg_class, url_encode(temp_timeperiod->name), html_encode(temp_timeperiod->name, FALSE));
			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_timeperiod->alias, FALSE));

			printf("<TD CLASS='%s'>", bg_class);
		}

		for (temp_timeperiodexclusion = temp_timeperiod->exclusions; temp_timeperiodexclusion != NULL; temp_timeperiodexclusion = temp_timeperiodexclusion->next) {
			if (temp_timeperiodexclusion != temp_timeperiod->exclusions)
				printf(", ");

			if (content_type == JSON_CONTENT)
				printf("\"%s\"", temp_timeperiodexclusion->timeperiod_name);
			else if (content_type == CSV_CONTENT)
				printf("%s", temp_timeperiodexclusion->timeperiod_name);
			else
				printf("<A HREF='#%s'>%s</A>", url_encode(temp_timeperiodexclusion->timeperiod_name), html_encode(temp_timeperiodexclusion->timeperiod_name, FALSE));
		}

			if (content_type == JSON_CONTENT) {
				printf(" ], ");
				printf("\"天/时间\": [ ");
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s", csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("</TD>\n");
				printf("<TD CLASS='%s'>", bg_class);
			}

		line = 0;
		for (x = 0; x < DATERANGE_TYPES; x++) {
			for (temp_daterange = temp_timeperiod->exceptions[x]; temp_daterange != NULL; temp_daterange = temp_daterange->next) {

				line++;

					if (line > 1) {
						if (content_type == JSON_CONTENT) {
							printf(", { \"天/日期\": \"");
						} else if (content_type == CSV_CONTENT) {
							printf("%s%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
							printf("%s%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
							printf("%s%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
							printf("%s", csv_data_enclosure);
						} else
							printf("<TR><TD COLSPAN='3'></TD>\n<TD CLASS='%s'>", bg_class);
					} else {
						if (content_type == JSON_CONTENT)
							printf("{ \"天/日期\": \"");
					}

					switch (temp_daterange->type) {
					case DATERANGE_CALENDAR_DATE:
						printf("%d-%02d-%02d", temp_daterange->syear, temp_daterange->smon + 1, temp_daterange->smday);
						if ((temp_daterange->smday != temp_daterange->emday) || (temp_daterange->smon != temp_daterange->emon) || (temp_daterange->syear != temp_daterange->eyear))
							printf(" - %d-%02d-%02d", temp_daterange->eyear, temp_daterange->emon + 1, temp_daterange->emday);
						if (temp_daterange->skip_interval > 1)
							printf(" / %d", temp_daterange->skip_interval);
						break;
					case DATERANGE_MONTH_DATE:
						printf("%s %d日", months[temp_daterange->smon], temp_daterange->smday);
						if ((temp_daterange->smon != temp_daterange->emon) || (temp_daterange->smday != temp_daterange->emday)) {
							printf(" - %s %d日", months[temp_daterange->emon], temp_daterange->emday);
							if (temp_daterange->skip_interval > 1)
								printf(" / %d", temp_daterange->skip_interval);
						}
						break;
					case DATERANGE_MONTH_DAY:
						printf("天 %d", temp_daterange->smday);
						if (temp_daterange->smday != temp_daterange->emday) {
							printf(" - %d日", temp_daterange->emday);
							if (temp_daterange->skip_interval > 1)
								printf(" / %d", temp_daterange->skip_interval);
						}
						break;
					case DATERANGE_MONTH_WEEK_DAY:
						printf("%s %d日 %s", days[temp_daterange->swday], temp_daterange->swday_offset, months[temp_daterange->smon]);
						if ((temp_daterange->smon != temp_daterange->emon) || (temp_daterange->swday != temp_daterange->ewday) || (temp_daterange->swday_offset != temp_daterange->ewday_offset)) {
							printf(" - %s %d日 %s", days[temp_daterange->ewday], temp_daterange->ewday_offset, months[temp_daterange->emon]);
							if (temp_daterange->skip_interval > 1)
								printf(" / %d", temp_daterange->skip_interval);
						}
						break;
					case DATERANGE_WEEK_DAY:
						printf("%s %d日", days[temp_daterange->swday], temp_daterange->swday_offset);
						if ((temp_daterange->swday != temp_daterange->ewday) || (temp_daterange->swday_offset != temp_daterange->ewday_offset)) {
							printf(" - %s %d日", days[temp_daterange->ewday], temp_daterange->ewday_offset);
							if (temp_daterange->skip_interval > 1)
								printf(" / %d", temp_daterange->skip_interval);
						}
						break;
					default:
						break;
					}

				if (content_type == JSON_CONTENT)
					printf("\", \"time\": [ ");
				else if (content_type == CSV_CONTENT) {
					printf("%s%s", csv_data_enclosure, csv_delimiter);
					printf("%s", csv_data_enclosure);
				} else
					printf("</TD>\n<TD CLASS='%s'>", bg_class);

				for (temp_timerange = temp_daterange->times; temp_timerange != NULL; temp_timerange = temp_timerange->next) {

					if (temp_timerange != temp_daterange->times)
						printf(", ");

					hours = temp_timerange->range_start / 3600;
					minutes = (temp_timerange->range_start - (hours * 3600)) / 60;
					seconds = temp_timerange->range_start - (hours * 3600) - (minutes * 60);
					snprintf(timestring, sizeof(timestring) - 1, "%02d:%02d:%02d", hours, minutes, seconds);
					timestring[sizeof(timestring) - 1] = '\x0';
					printf("%s%s - ", (content_type == JSON_CONTENT) ? "\"" : "", timestring);

					hours = temp_timerange->range_end / 3600;
					minutes = (temp_timerange->range_end - (hours * 3600)) / 60;
					seconds = temp_timerange->range_end - (hours * 3600) - (minutes * 60);
					snprintf(timestring, sizeof(timestring) - 1, "%02d:%02d:%02d", hours, minutes, seconds);
					timestring[sizeof(timestring) - 1] = '\x0';
					printf("%s%s", timestring, (content_type == JSON_CONTENT) ? "\"" : "");
				}

				if (content_type == JSON_CONTENT)
					printf(" ] }");
				else if (content_type == CSV_CONTENT)
					printf("%s\n", csv_data_enclosure);
				else {
					printf("</TD>\n");
					printf("</TR>\n");
				}
			}
		}
		for (day = 0; day < 7; day++) {

			if (temp_timeperiod->days[day] == NULL)
				continue;

			line++;

				if (line > 1) {
					if (content_type == JSON_CONTENT)
						printf(", { \"天/日期\": \"%s\",  \"时间\": [ ", days[day]);
					else if (content_type == CSV_CONTENT) {
						printf("%s%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
						printf("%s%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
						printf("%s%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
						printf("%s%s%s%s", csv_data_enclosure, days[day], csv_data_enclosure, csv_delimiter);
						printf("%s", csv_data_enclosure);
					} else
						printf("<TR><TD COLSPAN='3'></TD><TD CLASS='%s'>%s</TD><TD CLASS='%s'>", bg_class, days[day], bg_class);
				} else {
					if (content_type == JSON_CONTENT)
						printf("{ \"天/日期\": \"%s\",  \"时间\": [ ", days[day]);
					else if (content_type == CSV_CONTENT) {
						printf("%s%s%s", days[day], csv_data_enclosure, csv_delimiter);
						printf("%s", csv_data_enclosure);
					} else
						printf("%s</TD>\n<TD CLASS='%s'>", days[day], bg_class);
				}


			for (temp_timerange = temp_timeperiod->days[day]; temp_timerange != NULL; temp_timerange = temp_timerange->next) {

				if (temp_timerange != temp_timeperiod->days[day])
					printf(", ");

				hours = temp_timerange->range_start / 3600;
				minutes = (temp_timerange->range_start - (hours * 3600)) / 60;
				seconds = temp_timerange->range_start - (hours * 3600) - (minutes * 60);
				snprintf(timestring, sizeof(timestring) - 1, "%02d:%02d:%02d", hours, minutes, seconds);
				timestring[sizeof(timestring) - 1] = '\x0';
				printf("%s%s - ", (content_type == JSON_CONTENT) ? "\"" : "", timestring);

				hours = temp_timerange->range_end / 3600;
				minutes = (temp_timerange->range_end - (hours * 3600)) / 60;
				seconds = temp_timerange->range_end - (hours * 3600) - (minutes * 60);
				snprintf(timestring, sizeof(timestring) - 1, "%02d:%02d:%02d", hours, minutes, seconds);
				timestring[sizeof(timestring) - 1] = '\x0';
				printf("%s%s", timestring, (content_type == JSON_CONTENT) ? "\"" : "");
			}

			if (content_type == JSON_CONTENT)
				printf(" ] }");
			else if (content_type == CSV_CONTENT)
				printf("%s\n", csv_data_enclosure);
			else {
				printf("</TD>\n");
				printf("</TR>\n");
			}
		}

		if (content_type == JSON_CONTENT)
			printf(" ] }\n");

		if (line == 0 && content_type != JSON_CONTENT) {

			if (content_type == CSV_CONTENT) {
				printf("%s%s", csv_data_enclosure, csv_delimiter);
				printf("%s%s\n", csv_data_enclosure, csv_data_enclosure);
			} else {
				printf("</TD>\n<TD></TD>\n");
				printf("</TR>\n");
			}
		}
	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT)
		printf("</TABLE>\n");
	else if (content_type == JSON_CONTENT)
		printf("\n]\n");

	return;
}

void display_commands(void) {
	command *temp_command;
	int odd = 0;
	char *bg_class = "";
	int json_start = TRUE;

	if (content_type == JSON_CONTENT) {
		printf("\"命令\": [\n");
	} else if (content_type == CSV_CONTENT) {
		printf("%s命令名称%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s命令行%s", csv_data_enclosure, csv_data_enclosure);
		printf("\n");
	} else {
		printf("<TABLE BORDER=0 CLASS='data'>\n");
		printf("<TR><TH CLASS='data'>命令名称e</TH><TH CLASS='data'>命令行</TH></TR>\n");
	}

	/* check all commands */
	for (temp_command = command_list; temp_command != NULL; temp_command = temp_command->next) {

		if (item_name != NULL && strcmp(item_name, temp_command->name) != 0)
			continue;

		/* try to find a match */
		if (search_string != NULL && \
			regexec(&search_preg, temp_command->name, 0, NULL, 0) != 0 && \
		        regexec(&search_preg, temp_command->command_line, 0, NULL, 0) != 0)
				continue;

		if (result_limit != 0  && (((total_entries + 1) < result_start) || (total_entries >= ((result_start + result_limit) - 1)))) {
			total_entries++;
			continue;
		}

		displayed_entries++;
		total_entries++;

		if (odd) {
			odd = 0;
			bg_class = "dataEven";
		} else {
			odd = 1;
			bg_class = "dataOdd";
		}

		/* print list in json format */
		if (content_type == JSON_CONTENT) {
			// always add a comma, except for the first line
			if (json_start == FALSE)
				printf(",\n");
			json_start = FALSE;

				printf("{ \"命令名称\": \"%s\", ", json_encode(temp_command->name));
				printf("\"命令行\": \"%s\" }", json_encode(temp_command->command_line));
				/* print list in csv format */
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s%s%s", csv_data_enclosure, temp_command->name, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s\n", csv_data_enclosure, temp_command->command_line, csv_data_enclosure);
			} else {
				printf("<TR CLASS='%s'>\n", bg_class);

			printf("<TD CLASS='%s'><A NAME='%s'></A>%s</TD>\n", bg_class, url_encode(temp_command->name), html_encode(temp_command->name, FALSE));
			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_command->command_line, FALSE));

			printf("</TR>\n");
		}
	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT)
		printf("</TABLE>\n");
	else if (content_type == JSON_CONTENT)
		printf("\n]\n");

	return;
}

void display_servicedependencies(void) {
	servicedependency *temp_sd;
	char master_host_service_name[MAX_INPUT_BUFFER];
	char dependend_host_service_name[MAX_INPUT_BUFFER];
	char *bg_class = "";
	int odd = 0;
	int options;
	int json_start = TRUE;

	if (content_type == JSON_CONTENT) {
		printf("\"服务依赖\": [\n");
	} else if (content_type == CSV_CONTENT) {
        printf("%s依赖主机%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s依赖服务%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s主要主机%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s主要服务%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s依赖类型%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s依赖周期%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s依赖失败选项%s\n",csv_data_enclosure,csv_data_enclosure);
	} else {
		printf("<TABLE BORDER=0 CLASS='data'>\n");
		printf("<TR>\n");
		printf("<TH CLASS='data' COLSPAN=2>依赖服务</TH>");
		printf("<TH CLASS='data' COLSPAN=2>主要服务</TH>");
		printf("</TR>\n");
		printf("<TR>\n");
		printf("<TH CLASS='data'>主机</TH>");
		printf("<TH CLASS='data'>服务</TH>");
		printf("<TH CLASS='data'>主机</TH>");
		printf("<TH CLASS='data'>服务</TH>");
		printf("<TH CLASS='data'>依赖类型</TH>");
		printf("<TH CLASS='data'>依赖周期</TH>");
		printf("<TH CLASS='data'>依赖失败选项</TH>");
		printf("</TR>\n");
	}

	/* check all the service dependencies... */
	for (temp_sd = servicedependency_list; temp_sd != NULL; temp_sd = temp_sd->next) {

		/* try to match on combination of host name and service description */
		snprintf(master_host_service_name, sizeof(master_host_service_name), "%s %s", temp_sd->host_name, temp_sd->service_description);
		master_host_service_name[sizeof(master_host_service_name) - 1] = '\x0';
		snprintf(dependend_host_service_name, sizeof(dependend_host_service_name), "%s %s", temp_sd->dependent_host_name, temp_sd->dependent_service_description);
		dependend_host_service_name[sizeof(dependend_host_service_name) - 1] = '\x0';


		/* try to find a match */
		if (search_string != NULL && \
			regexec(&search_preg, master_host_service_name, 0, NULL, 0) != 0 && \
		        regexec(&search_preg, dependend_host_service_name, 0, NULL, 0) != 0)
				continue;

		if (result_limit != 0  && (((total_entries + 1) < result_start) || (total_entries >= ((result_start + result_limit) - 1)))) {
			total_entries++;
			continue;
		}

		displayed_entries++;
		total_entries++;

		if (odd) {
			odd = 0;
			bg_class = "dataOdd";
		} else {
			odd = 1;
			bg_class = "dataEven";
		}

		/* print list in json format */
		if (content_type == JSON_CONTENT) {
			// always add a comma, except for the first line
			if (json_start == FALSE)
				printf(",\n");
			json_start = FALSE;

				printf("{ \"依赖主机名称\": \"%s\", ", json_encode(temp_sd->dependent_host_name));
				printf("\"依赖服描述\": \"%s\", ", json_encode(temp_sd->dependent_service_description));
				printf("\"主要主机名称\": \"%s\", ", json_encode(temp_sd->host_name));
				printf("\"主要服务描述\": \"%s\", ", json_encode(temp_sd->service_description));
				printf("\"依赖类型\": \"%s\", ", (temp_sd->dependency_type == NOTIFICATION_DEPENDENCY) ? "通知" : "检查执行");

				if (temp_sd->dependency_period == NULL)
					printf("\"依赖周期\": null, ");
				else
					printf("\"依赖周期\": \"%s\", ", json_encode(temp_sd->dependency_period));

				printf("\"依赖失败选项\": [");
				/* print list in csv format */
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s%s%s", csv_data_enclosure, temp_sd->dependent_host_name, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, temp_sd->dependent_service_description, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, temp_sd->host_name, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, temp_sd->service_description, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_sd->dependency_type == NOTIFICATION_DEPENDENCY) ? "通知" : "检查执行", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_sd->dependency_period == NULL) ? "" : temp_sd->dependency_period, csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("<TR CLASS='%s'>\n", bg_class);

			printf("<TD CLASS='%s'><A HREF='%s?type=hosts&item_name=%s'>%s</A></TD>\n", bg_class, CONFIG_CGI, url_encode(temp_sd->dependent_host_name), html_encode(temp_sd->dependent_host_name, FALSE));

			printf("<TD CLASS='%s'><A HREF='%s?type=services&item_name=%s^", bg_class, CONFIG_CGI, url_encode(temp_sd->dependent_host_name));
			printf("%s'>%s</A></TD>\n", url_encode(temp_sd->dependent_service_description), html_encode(temp_sd->dependent_service_description, FALSE));

			printf("<TD CLASS='%s'><A HREF='%s?type=hosts&item_name=%s'>%s</A></TD>\n", bg_class, CONFIG_CGI, url_encode(temp_sd->host_name), html_encode(temp_sd->host_name, FALSE));

			printf("<TD CLASS='%s'><A HREF='%s?type=services&item_name=%s^", bg_class, CONFIG_CGI, url_encode(temp_sd->host_name));
			printf("%s'>%s</A></TD>\n", url_encode(temp_sd->service_description), html_encode(temp_sd->service_description, FALSE));

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_sd->dependency_type == NOTIFICATION_DEPENDENCY) ? "通知" : "检查执行");

			printf("<TD CLASS='%s'>", bg_class);
			if (temp_sd->dependency_period == NULL)
				printf("&nbsp;");
			else
				printf("<A HREF='%s?type=timeperiods&item_name=%s'>%s</A>", CONFIG_CGI, url_encode(temp_sd->dependency_period), html_encode(temp_sd->dependency_period, FALSE));
			printf("</TD>\n");

			printf("<TD CLASS='%s'>", bg_class);
		}

			options = 0;
			if (temp_sd->fail_on_ok == TRUE) {
				printf("%s正常%s", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_sd->fail_on_warning == TRUE) {
				printf("%s%s警报%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_sd->fail_on_unknown == TRUE) {
				printf("%s%s未知%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_sd->fail_on_critical == TRUE) {
				printf("%s%s严重%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_sd->fail_on_pending == TRUE) {
				printf("%s%s未决%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (options == 0 && content_type != JSON_CONTENT)
				printf("无");

		if (content_type == JSON_CONTENT)
			printf(" ] }");
		else if (content_type == CSV_CONTENT)
			printf("%s\n", csv_data_enclosure);
		else
			printf("</TD>\n</TR>\n");
	}


	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT)
		printf("</TABLE>\n");
	else if (content_type == JSON_CONTENT)
		printf("\n]\n");

	return;
}

void display_serviceescalations(void) {
	serviceescalation *temp_se = NULL;
	contactsmember *temp_contactsmember = NULL;
	contactgroupsmember *temp_contactgroupsmember = NULL;
	char time_string[16] = "";
	int options = FALSE;
	int odd = 0;
	char *bg_class = "";
	int contact = 0;
	int json_start = TRUE;

	if (content_type == JSON_CONTENT) {
		printf("\"服务增强\": [\n");
	} else if (content_type == CSV_CONTENT) {
        printf("%s主机%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s描述%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s联系人/组%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s首次通知%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s最后通知%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s通知间隔%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s增强周期%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s增强选项%s\n",csv_data_enclosure,csv_data_enclosure);
	} else {
		printf("<TABLE BORDER=0 CLASS='data'>\n");
		printf("<TR>\n");
		printf("<TH CLASS='data'>主机</TH>");
		printf("<TH CLASS='data'>描述</TH>");
		printf("<TH CLASS='data'>联系人/组</TH>");
		printf("<TH CLASS='data'>首次通知</TH>");
		printf("<TH CLASS='data'>最后通知</TH>");
		printf("<TH CLASS='data'>通知间隔</TH>");
		printf("<TH CLASS='data'>增强周期</TH>");
		printf("<TH CLASS='data'>增强选项</TH>");
		printf("</TR>\n");
	}

	/* check all the service escalations... */
	for (temp_se = serviceescalation_list; temp_se != NULL; temp_se = temp_se->next) {

		/* try to find a match */
		if (search_string != NULL && \
			regexec(&search_preg, temp_se->host_name, 0, NULL, 0) != 0 && \
		        regexec(&search_preg, temp_se->description, 0, NULL, 0) != 0)
				continue;

		if (result_limit != 0  && (((total_entries + 1) < result_start) || (total_entries >= ((result_start + result_limit) - 1)))) {
			total_entries++;
			continue;
		}

		displayed_entries++;
		total_entries++;

		if (odd) {
			odd = 0;
			bg_class = "dataOdd";
		} else {
			odd = 1;
			bg_class = "dataEven";
		}

		/* print list in json format */
		if (content_type == JSON_CONTENT) {
			// always add a comma, except for the first line
			if (json_start == FALSE)
				printf(",\n");
			json_start = FALSE;

				printf("{ \"主机名称\": \"%s\", ", json_encode(temp_se->host_name));
				printf("\"服务描述\": \"%s\", ", json_encode(temp_se->description));
				printf("\"联系人/组\": [");
				/* print list in csv format */
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s%s%s", csv_data_enclosure, temp_se->host_name, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, temp_se->description, csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("<TR CLASS='%s'>\n", bg_class);

			printf("<TD CLASS='%s'><A HREF='%s?type=hosts&item_name=%s'>%s</A></TD>\n", bg_class, CONFIG_CGI, url_encode(temp_se->host_name), html_encode(temp_se->host_name, FALSE));

			printf("<TD CLASS='%s'><A HREF='%s?type=services&item_name=%s^", bg_class, CONFIG_CGI, url_encode(temp_se->host_name));
			printf("%s'>%s</A></TD>\n", url_encode(temp_se->description), html_encode(temp_se->description, FALSE));

			printf("<TD CLASS='%s'>", bg_class);
		}

		contact = 0;
		for (temp_contactsmember = temp_se->contacts; temp_contactsmember != NULL; temp_contactsmember = temp_contactsmember->next) {
			contact++;
			if (contact > 1)
				printf(", ");

			if (content_type == JSON_CONTENT)
				printf("{ \"联系人名称\": \"%s\" } ", json_encode(temp_contactsmember->contact_name));
			else if (content_type == CSV_CONTENT)
				printf("%s", temp_contactsmember->contact_name);
			else
				printf("<A HREF='%s?type=contacts&item_name=%s'>%s</A>\n", CONFIG_CGI, url_encode(temp_contactsmember->contact_name), html_encode(temp_contactsmember->contact_name, FALSE));
		}
		for (temp_contactgroupsmember = temp_se->contact_groups; temp_contactgroupsmember != NULL; temp_contactgroupsmember = temp_contactgroupsmember->next) {
			contact++;
			if (contact > 1)
				printf(", ");

			if (content_type == JSON_CONTENT)
				printf("{ \"联系人组名称\": \"%s\" } ", json_encode(temp_contactgroupsmember->group_name));
			else if (content_type == CSV_CONTENT)
				printf("%s", temp_contactgroupsmember->group_name);
			else
				printf("<A HREF='%s?type=contactgroups&item_name=%s'>%s</A>\n", CONFIG_CGI, url_encode(temp_contactgroupsmember->group_name), html_encode(temp_contactgroupsmember->group_name, FALSE));
		}
		if (contact == 0)
			printf("%s", (content_type == CSV_CONTENT || content_type == JSON_CONTENT) ? "" : "&nbsp;");

		if (content_type == JSON_CONTENT) {
			printf(" ], ");
			printf("\"首次通知\": %d, ", temp_se->first_notification);
			/* state based escalation ranges */
			printf("\"首次警报通知\": %d, ", temp_se->first_warning_notification);
			printf("\"首次严重通知\": %d, ", temp_se->first_critical_notification);
			printf("\"首次未知通知\": %d, ", temp_se->first_unknown_notification);

			if (temp_se->last_notification == 0)
				printf("\"最近通知\": null, ");
			else
				printf("\"最近通知\": %d, ", temp_se->last_notification);
			/* state based escalation ranges */
			if (temp_se->last_warning_notification == 0)
				printf("\"最近警报通知\": null, ");
			else
				printf("\"最近警报通知\": %d, ", temp_se->last_warning_notification);
			if (temp_se->last_critical_notification == 0)
				printf("\"最近严重通知\": null, ");
			else
				printf("\"最近严重通知\": %d, ", temp_se->last_critical_notification);
			if (temp_se->last_unknown_notification == 0)
				printf("\"最近未知通知\": null, ");
			else
				printf("\"最近未知通知\": %d, ", temp_se->last_unknown_notification);
		} else if (content_type == CSV_CONTENT) {
			printf("%s%s", csv_data_enclosure, csv_delimiter);

			/* state based escalation ranges */
			printf("%s%d, %d, %d, %d%s%s", csv_data_enclosure, temp_se->first_notification, temp_se->first_warning_notification, temp_se->first_critical_notification, temp_se->first_unknown_notification, csv_data_enclosure, csv_delimiter);
			printf("%s", csv_data_enclosure);
		} else {
			printf("</TD>\n");

			/* state based escalation ranges */
			printf("<TD CLASS='%s'>%d, %d, %d, %d</TD>\n", bg_class, temp_se->first_notification, temp_se->first_warning_notification, temp_se->first_critical_notification, temp_se->first_unknown_notification);

			printf("<TD CLASS='%s'>", bg_class);
		}

		if (content_type != JSON_CONTENT) {
			/* state based escalation ranges */
			if (temp_se->last_notification == 0)
				printf("不限, ");
			else
				printf("%d, ", temp_se->last_notification);
			if (temp_se->last_warning_notification == 0)
				printf("不限, ");
			else
				printf("%d, ", temp_se->last_warning_notification);
			if (temp_se->last_critical_notification == 0)
				printf("不限, ");
			else
				printf("%d, ", temp_se->last_critical_notification);
			if (temp_se->last_unknown_notification == 0)
				printf("不限");
			else
				printf("%d", temp_se->last_unknown_notification);
		}

		get_interval_time_string(temp_se->notification_interval, time_string, sizeof(time_string));

			if (content_type == JSON_CONTENT) {
				printf("\"通知间隔\": \"%s\", ", (temp_se->notification_interval == 0.0) ? "一次性通知(不重复通知)" : time_string);
				if (temp_se->escalation_period == NULL)
					printf("\"增强周期\": null, ");
				else
					printf("\"增强周期\": \"%s\", ", json_encode(temp_se->escalation_period));
				printf("\"增强选项\": [ ");
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_se->notification_interval == 0.0) ? "一次性通知(不重复通知)" : time_string, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_se->escalation_period == NULL) ? "" : temp_se->escalation_period, csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("</TD>\n");

				printf("<TD CLASS='%s'>", bg_class);
				if (temp_se->notification_interval == 0.0)
					printf("一次性通知(不重复通知)");
				else
					printf("%s", time_string);
				printf("</TD>\n");

			printf("<TD CLASS='%s'>", bg_class);
			if (temp_se->escalation_period == NULL)
				printf("&nbsp;");
			else
				printf("<A HREF='%s?type=timeperiods&item_name=%s'>%s</A>", CONFIG_CGI, url_encode(temp_se->escalation_period), html_encode(temp_se->escalation_period, FALSE));
			printf("</TD>\n");

			printf("<TD CLASS='%s'>", bg_class);
		}

			options = 0;
			if (temp_se->escalate_on_warning == TRUE) {
				printf("%s报警%s", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_se->escalate_on_unknown == TRUE) {
				printf("%s%s未知%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_se->escalate_on_critical == TRUE) {
				printf("%s%s严重%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_se->escalate_on_recovery == TRUE) {
				printf("%s%s恢复%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (options == 0 && content_type != JSON_CONTENT)
				printf("无");

		if (content_type == JSON_CONTENT)
			printf(" ] }");
		else if (content_type == CSV_CONTENT)
			printf("%s\n", csv_data_enclosure);
		else
			printf("</TD>\n</TR>\n");
	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT)
		printf("</TABLE>\n");
	else if (content_type == JSON_CONTENT)
		printf("\n]\n");

	return;
}

void display_hostdependencies(void) {
	hostdependency *temp_hd;
	int odd = 0;
	int options;
	char *bg_class = "";
	int json_start = TRUE;

	if (content_type == JSON_CONTENT) {
		printf("\"主机依赖\": [\n");
	} else if (content_type == CSV_CONTENT) {
		printf("%s依赖主机%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s主要主机%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s依赖类型%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s依赖周期%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s依赖失败选项%s\n", csv_data_enclosure, csv_data_enclosure);
	} else {
		printf("<TABLE BORDER=0 CLASS='data'>\n");
		printf("<TR>\n");
		printf("<TH CLASS='data'>依赖主机</TH>");
		printf("<TH CLASS='data'>主要主机</TH>");
		printf("<TH CLASS='data'>依赖类型</TH>");
		printf("<TH CLASS='data'>依赖周期</TH>");
		printf("<TH CLASS='data'>依赖失败选项</TH>");
		printf("</TR>\n");
	}

	/* check all the host dependencies... */
	for (temp_hd = hostdependency_list; temp_hd != NULL; temp_hd = temp_hd->next) {

		/* try to find a match */
		if (search_string != NULL && \
			regexec(&search_preg, temp_hd->dependent_host_name, 0, NULL, 0) != 0 && \
		        regexec(&search_preg, temp_hd->host_name, 0, NULL, 0) != 0)
				continue;

		if (result_limit != 0  && (((total_entries + 1) < result_start) || (total_entries >= ((result_start + result_limit) - 1)))) {
			total_entries++;
			continue;
		}

		displayed_entries++;
		total_entries++;

		if (odd) {
			odd = 0;
			bg_class = "dataOdd";
		} else {
			odd = 1;
			bg_class = "dataEven";
		}

		/* print list in json format */
		if (content_type == JSON_CONTENT) {
			// always add a comma, except for the first line
			if (json_start == FALSE)
				printf(",\n");
			json_start = FALSE;

				printf("{ \"依赖主机名称\": \"%s\", ", json_encode(temp_hd->dependent_host_name));
				printf("\"主要主机名称\": \"%s\", ", json_encode(temp_hd->host_name));
				printf("\"依赖类型\": \"%s\", ", (temp_hd->dependency_type == NOTIFICATION_DEPENDENCY) ? "通知" : "检查执行");

				if (temp_hd->dependency_period == NULL)
					printf("\"依赖周期\": null, ");
				else
					printf("\"依赖周期\": \"%s\", ", json_encode(temp_hd->dependency_period));

				printf("\"依赖失败选项\": [");
				/* print list in csv format */
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s%s%s", csv_data_enclosure, temp_hd->dependent_host_name, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, temp_hd->host_name, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_hd->dependency_type == NOTIFICATION_DEPENDENCY) ? "通知" : "检查执行", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_hd->dependency_period == NULL) ? "" : temp_hd->dependency_period, csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("<TR CLASS='%s'>\n", bg_class);

			printf("<TD CLASS='%s'><A HREF='%s?type=hosts&item_name=%s'>%s</A></TD>\n", bg_class, CONFIG_CGI, url_encode(temp_hd->dependent_host_name), html_encode(temp_hd->dependent_host_name, FALSE));

			printf("<TD CLASS='%s'><A HREF='%s?type=hosts&item_name=%s'>%s</A></TD>\n", bg_class, CONFIG_CGI, url_encode(temp_hd->host_name), html_encode(temp_hd->host_name, FALSE));

				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_hd->dependency_type == NOTIFICATION_DEPENDENCY) ? "通知" : "检查执行");

			printf("<TD CLASS='%s'>", bg_class);
			if (temp_hd->dependency_period == NULL)
				printf("&nbsp;");
			else
				printf("<A HREF='%s?type=timeperiods&item_name=%s'>%s</A>", CONFIG_CGI, url_encode(temp_hd->dependency_period), html_encode(temp_hd->dependency_period, FALSE));
			printf("</TD>\n");

			printf("<TD CLASS='%s'>", bg_class);
		}

			options = 0;
			if (temp_hd->fail_on_up == TRUE) {
				printf("%s运行%s", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_hd->fail_on_down == TRUE) {
				printf("%s%s宕机%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_hd->fail_on_unreachable == TRUE) {
				printf("%s%s不可达%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_hd->fail_on_pending == TRUE) {
				printf("%s%s未决%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}

		if (options == 0 && content_type != JSON_CONTENT)
			printf("None");

		if (content_type == JSON_CONTENT)
			printf(" ] }");
		else if (content_type == CSV_CONTENT)
			printf("%s\n", csv_data_enclosure);
		else
			printf("</TD>\n</TR>\n");
	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT)
		printf("</TABLE>\n");
	else if (content_type == JSON_CONTENT)
		printf("\n]\n");

	return;
}

void display_hostescalations(void) {
	hostescalation *temp_he = NULL;
	contactsmember *temp_contactsmember = NULL;
	contactgroupsmember *temp_contactgroupsmember = NULL;
	char time_string[16] = "";
	int options = FALSE;
	int odd = 0;
	char *bg_class = "";
	int contact = 0;
	int json_start = TRUE;

	if (content_type == JSON_CONTENT) {
		printf("\"主机增强\": [\n");
	} else if (content_type == CSV_CONTENT) {
		printf("%s主机%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s联系人/组%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s首次通知%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s最后通知%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s通知间隔%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s增强周期%s%s",csv_data_enclosure,csv_data_enclosure,csv_delimiter);
		printf("%s增强选项%s\n",csv_data_enclosure,csv_data_enclosure);
	} else {
		printf("<TABLE BORDER=0 CLASS='data'>\n");
		printf("<TR>\n");
		printf("<TH CLASS='data'>主机</TH>");
		printf("<TH CLASS='data'>联系人/组</TH>");
		printf("<TH CLASS='data'>首次通知</TH>");
		printf("<TH CLASS='data'>最后通知</TH>");
		printf("<TH CLASS='data'>通知间隔</TH>");
		printf("<TH CLASS='data'>增强周期</TH>");
		printf("<TH CLASS='data'>增强选项</TH>");
		printf("</TR>\n");
	}

	/* check all the host escalations... */
	for (temp_he = hostescalation_list; temp_he != NULL; temp_he = temp_he->next) {

		/* try to find a match */
		if (search_string != NULL && \
		        regexec(&search_preg, temp_he->host_name, 0, NULL, 0) != 0)
				continue;

		if (result_limit != 0  && (((total_entries + 1) < result_start) || (total_entries >= ((result_start + result_limit) - 1)))) {
			total_entries++;
			continue;
		}

		displayed_entries++;
		total_entries++;

		if (odd) {
			odd = 0;
			bg_class = "dataOdd";
		} else {
			odd = 1;
			bg_class = "dataEven";
		}

		/* print list in json format */
		if (content_type == JSON_CONTENT) {
			// always add a comma, except for the first line
			if (json_start == FALSE)
				printf(",\n");
			json_start = FALSE;

				printf("{ \"主机名称\": \"%s\", ", json_encode(temp_he->host_name));
				printf("\"联系人/组\": [");
				/* print list in csv format */
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s%s%s", csv_data_enclosure, temp_he->host_name, csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("<TR CLASS='%s'>\n", bg_class);

			printf("<TD CLASS='%s'><A HREF='%s?type=hosts&item_name=%s'>%s</A></TD>\n", bg_class, CONFIG_CGI, url_encode(temp_he->host_name), html_encode(temp_he->host_name, FALSE));

			printf("<TD CLASS='%s'>", bg_class);
		}
		contact = 0;
		for (temp_contactsmember = temp_he->contacts; temp_contactsmember != NULL; temp_contactsmember = temp_contactsmember->next) {
			contact++;
			if (contact > 1)
				printf(", ");
			if (content_type == JSON_CONTENT)
				printf("{ \"联系人名称\": \"%s\" } ", json_encode(temp_contactsmember->contact_name));
			else if (content_type == CSV_CONTENT)
				printf("%s", temp_contactsmember->contact_name);
			else
				printf("<A HREF='%s?type=contacts&item_name=%s'>%s</A>\n", CONFIG_CGI, url_encode(temp_contactsmember->contact_name), html_encode(temp_contactsmember->contact_name, FALSE));
		}
		for (temp_contactgroupsmember = temp_he->contact_groups; temp_contactgroupsmember != NULL; temp_contactgroupsmember = temp_contactgroupsmember->next) {
			contact++;
			if (contact > 1)
				printf(", ");
			if (content_type == JSON_CONTENT)
				printf("{ \"联系人组名称\": \"%s\" } ", json_encode(temp_contactgroupsmember->group_name));
			else if (content_type == CSV_CONTENT)
				printf("%s", temp_contactgroupsmember->group_name);
			else
				printf("<A HREF='%s?type=contactgroups&item_name=%s'>%s</A>\n", CONFIG_CGI, url_encode(temp_contactgroupsmember->group_name), html_encode(temp_contactgroupsmember->group_name, FALSE));
		}
		if (contact == 0)
			printf("%s", (content_type == CSV_CONTENT || content_type == JSON_CONTENT) ? "" : "&nbsp;");

		if (content_type == JSON_CONTENT) {
			printf(" ], ");
			printf("\"首次通知\": %d, ", temp_he->first_notification);
			/* state based escalation ranges */
			printf("\"首次宕机通知\": %d, ", temp_he->first_down_notification);
			printf("\"首次不可达通知\": %d, ", temp_he->first_unreachable_notification);

			if (temp_he->last_notification == 0)
				printf("\"最近通知\": null, ");
			else
				printf("\"最近通知\": %d, ", temp_he->last_notification);
			/* state based escalation ranges */
			if (temp_he->last_down_notification == 0)
				printf("\"最近宕机通知\": null, ");
			else
				printf("\"最近宕机通知\": %d, ", temp_he->last_down_notification);
			if (temp_he->last_unreachable_notification == 0)
				printf("\"最近不可达通知\": null, ");
			else
				printf("\"最近不可达通知\": %d, ", temp_he->last_unreachable_notification);
		} else if (content_type == CSV_CONTENT) {
			printf("%s%s", csv_data_enclosure, csv_delimiter);

			/* state based escalation ranges */
			printf("%s%d, %d, %d%s%s", csv_data_enclosure, temp_he->first_notification, temp_he->first_down_notification, temp_he->first_unreachable_notification, csv_data_enclosure, csv_delimiter);
			printf("%s", csv_data_enclosure);
		} else {
			printf("</TD>\n");

			/* state based escalation ranges */
			printf("<TD CLASS='%s'>%d, %d, %d</TD>", bg_class, temp_he->first_notification, temp_he->first_down_notification, temp_he->first_unreachable_notification);
			printf("<TD CLASS='%s'>", bg_class);
		}

		if (content_type != JSON_CONTENT) {
			/* state based escalation ranges */
			if (temp_he->last_notification == 0)
				printf("不限, ");
			else
				printf("%d, ", temp_he->last_notification);
			if (temp_he->last_down_notification == 0)
				printf("不限, ");
			else
				printf("%d, ", temp_he->last_down_notification);
			if (temp_he->last_unreachable_notification == 0)
				printf("不限");
			else
				printf("%d", temp_he->last_unreachable_notification);
		}

		get_interval_time_string(temp_he->notification_interval, time_string, sizeof(time_string));

			if (content_type == JSON_CONTENT) {
				printf("\"通知间隔\": \"%s\", ", (temp_he->notification_interval == 0.0) ? "一次性通知(不重复通知)" : time_string);
				if (temp_he->escalation_period == NULL)
					printf("\"增强周期\": null, ");
				else
					printf("\"增强周期\": \"%s\", ", json_encode(temp_he->escalation_period));
				printf("\"增强选项\": [ ");
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s", csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_he->notification_interval == 0.0) ? "一次性通知(不重复通知)" : time_string, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, (temp_he->escalation_period == NULL) ? "" : temp_he->escalation_period, csv_data_enclosure, csv_delimiter);
				printf("%s", csv_data_enclosure);
			} else {
				printf("</TD>\n");
				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, (temp_he->notification_interval == 0.0) ? "一次性通知(不重复通知)" : time_string);

			printf("<TD CLASS='%s'>", bg_class);
			if (temp_he->escalation_period == NULL)
				printf("&nbsp;");
			else
				printf("<A HREF='%s?type=timeperiods&item_name=%s'>%s</A>", CONFIG_CGI, url_encode(temp_he->escalation_period), html_encode(temp_he->escalation_period, FALSE));
			printf("</TD>\n");

			printf("<TD CLASS='%s'>", bg_class);
		}

			options = 0;
			if (temp_he->escalate_on_down == TRUE) {
				printf("%s宕机%s", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_he->escalate_on_unreachable == TRUE) {
				printf("%s%s不可达%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (temp_he->escalate_on_recovery == TRUE) {
				printf("%s%s恢复%s", (options) ? ", " : "", (content_type == JSON_CONTENT) ? "\"" : "", (content_type == JSON_CONTENT) ? "\"" : "");
				options = 1;
			}
			if (options == 0 && content_type != JSON_CONTENT)
				printf("无");

		if (content_type == JSON_CONTENT)
			printf(" ] }");
		else if (content_type == CSV_CONTENT)
			printf("%s\n", csv_data_enclosure);
		else
			printf("</TD>\n</TR>\n");
	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT)
		printf("</TABLE>\n");
	else if (content_type == JSON_CONTENT)
		printf("\n]\n");

	return;
}

void display_modules(void) {
	module *temp_module;
	int odd = 0;
	char *bg_class = "";
	int json_start = TRUE;

	if (content_type == JSON_CONTENT) {
		printf("\"模块\": [\n");
	} else if (content_type == CSV_CONTENT) {
		printf("%s模块名称%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s模块类型%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s模块路径%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s模块参数%s", csv_data_enclosure, csv_data_enclosure);
		printf("\n");
	} else {
		printf("<TABLE BORDER=0 CLASS='data'>\n");
		printf("<TR><TH CLASS='data'>模块名称</TH><TH CLASS='data'>模块类型</TH><TH CLASS='data'>模块路径</TH><TH CLASS='data'>模块参数</TH></TR>\n");
	}

	/* check all modules */
	for (temp_module = module_list; temp_module != NULL; temp_module = temp_module->next) {

		if (item_name != NULL && strcmp(item_name, temp_module->name) != 0)
			continue;

		/* try to find a match */
		if (search_string != NULL && \
			regexec(&search_preg, temp_module->name, 0, NULL, 0) != 0 && \
			regexec(&search_preg, temp_module->path, 0, NULL, 0) != 0 && \
		        regexec(&search_preg, temp_module->args, 0, NULL, 0) != 0)
				continue;

		if (result_limit != 0  && (((total_entries + 1) < result_start) || (total_entries >= ((result_start + result_limit) - 1)))) {
			total_entries++;
			continue;
		}

		displayed_entries++;
		total_entries++;

		if (odd) {
			odd = 0;
			bg_class = "dataEven";
		} else {
			odd = 1;
			bg_class = "dataOdd";
		}

		/* print list in json format */
		if (content_type == JSON_CONTENT) {
			// always add a comma, except for the first line
			if (json_start == FALSE)
				printf(",\n");
			json_start = FALSE;

				printf("{ \"模块名称\": \"%s\", ", json_encode(temp_module->name));
				printf("\"模块类型\": \"%s\", ", json_encode(temp_module->type));
				printf("\"模块路\": \"%s\", ", json_encode(temp_module->path));
				printf("\"模块参数\": \"%s\" }", json_encode(temp_module->args));
				/* print list in csv format */
			} else if (content_type == CSV_CONTENT) {
				printf("%s%s%s%s", csv_data_enclosure, temp_module->name, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, temp_module->type, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s%s", csv_data_enclosure, temp_module->path, csv_data_enclosure, csv_delimiter);
				printf("%s%s%s\n", csv_data_enclosure, temp_module->args, csv_data_enclosure);
			} else {
				printf("<TR CLASS='%s'>\n", bg_class);

			printf("<TD CLASS='%s'><A NAME='%s'></A>%s</TD>\n", bg_class, url_encode(temp_module->name), html_encode(temp_module->name, FALSE));
			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_module->type, FALSE));
			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_module->path, FALSE));
			printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_module->args, FALSE));

			printf("</TR>\n");
		}
	}

	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT)
		printf("</TABLE>\n");
	else if (content_type == JSON_CONTENT)
		printf("\n]\n");

	return;
}

void display_cgiconfig(void) {
	int odd = 0;
	int json_start = TRUE;
	char *temp_ptr;

	/** BEGIN MACRO declaration */

	/** @brief Macro to expand a config line with an integer value
	 *  @param [in] var        the var name with the value AFTER config file was parsed
	 *  @param [in] org_var    the var name with the value BEFORE config file was parsed
	 *			   name of org_var also determines the option name
	 *  @param [in] type       can be "int" or "bool"
	 *  @warning It is important  that the org_var var name is a concatenation of "org_"
	 *	     and the option name. i.E. option is called "foo_bar", then org_var
	 *	     MUST be named "org_foo_bar".
	 *
	 *  Macro to print one config option of type int. "bool" adds TRUE & FALSE to HTML output
	 *  and "int" prints just plain numbers
	**/
#define PRINT_CONFIG_LINE_INT(var,org_var,type) \
	/* prints a config line with type int */ \
	if (content_type == JSON_CONTENT) { \
		/* always add a comma, except for the first line */ \
		if (json_start == FALSE) \
			printf(",\n"); \
		json_start = FALSE; \
		printf("{ \"配置选项名称\": \"%s\", ", json_encode(#org_var + 4)); \
		if (!strcmp(type, "bool")) { \
			printf("\"默认设置\": %s, ", (org_var == 1) ? "true" : "false"); \
			printf("\"当前设置\": %s }", (var == 1) ? "true" : "false"); \
		} else \
			printf("\"默认设置\": %d, \"当前设置\": %d }", org_var, var); \
	} else if (content_type == CSV_CONTENT) { \
		printf("%s%s%s%s", csv_data_enclosure, #org_var + 4, csv_data_enclosure, csv_delimiter); \
		printf("%s%d%s%s", csv_data_enclosure, org_var, csv_data_enclosure, csv_delimiter); \
		printf("%s%d%s\n", csv_data_enclosure, var, csv_data_enclosure); \
	} else { \
		odd = (odd == 0) ? 1 : 0; \
		if (!strcmp(type, "bool")) { \
			printf("<TR CLASS='%s'><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%d (%s)&nbsp;</TD><TD %s>&nbsp;%d (%s)&nbsp;</TD><TR>\n", \
			(odd == 0) ? "dataEven" : "dataOdd", #org_var + 4 , org_var, (org_var == 1) ? "TRUE" : "FALSE", \
			(var != org_var) ? "CLASS='dataDiff'" : "" , var, (var == 1) ? "TRUE" : "FALSE"); \
		} else { \
			printf("<TR CLASS='%s'><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%d&nbsp;</TD><TD %s>&nbsp;%d&nbsp;</TD><TR>\n", \
			(odd == 0) ? "dataEven" : "dataOdd", #org_var + 4, org_var, (var != org_var) ? "CLASS='dataDiff'" : "" , var); \
		} \
	}

	/** @brief Macro to expand a config line with an char/string value
	 *  @param [in] var        the var name with the value AFTER config file was parsed
	 *  @param [in] org_var    the var name with the value BEFORE config file was parsed
	 *			   name of org_var also determines the option name
	 *  @warning It is important  that the org_var var name is a concatenation of "org_"
	 *	     and the option name. i.E. option is called "foo_bar", then org_var
	 *	     MUST be named "org_foo_bar".
	 *
	 *  Macro to print one config option of type char.
	**/

#define PRINT_CONFIG_LINE_STRING(var,org_var) \
	/* prints a config line with type char */ \
	if (content_type == JSON_CONTENT) { \
		/* always add a comma, except for the first line */ \
		if (json_start == FALSE) \
			printf(",\n"); \
		json_start = FALSE; \
		printf("{ \"配置选项设置\": \"%s\", ", json_encode(#org_var + 4)); \
		printf("\"默认设置\": \"%s\", ", (strlen(org_var) == 0) ? "" : json_encode(org_var)); \
		printf("\"当前设置\": \"%s\" }", (strlen(var) == 0) ? "" : json_encode(var)); \
	} else if (content_type == CSV_CONTENT) { \
		printf("%s%s%s%s", csv_data_enclosure, #org_var + 4, csv_data_enclosure, csv_delimiter); \
		printf("%s%s%s%s", csv_data_enclosure, org_var, csv_data_enclosure, csv_delimiter); \
		printf("%s%s%s\n", csv_data_enclosure, var, csv_data_enclosure); \
	} else { \
		odd = (odd == 0) ? 1 : 0; \
		printf("<TR CLASS='%s'><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD %s>&nbsp;%s&nbsp;</TD><TR>\n", \
		(odd == 0) ? "dataEven" : "dataOdd", #org_var + 4, (strlen(org_var) == 0) ? "&lt;EMPTY&gt;" : html_encode(org_var, FALSE), \
		(!strcmp(var, org_var)) ? "" : "CLASS='dataDiff'", (strlen(var) == 0) ? "&lt;EMPTY&gt;" : html_encode(var, FALSE)); \
	}

	/** @brief Macro to expand a config line with authentication information
	 *
	 *  this macro creates links to the contact and contactgroup information
	**/
#define PRINT_CONFIG_LINE_AUTH(var,org_var) \
	/* prints a config line with type char and authorization information */ \
	if (content_type == JSON_CONTENT || content_type == CSV_CONTENT) { \
		PRINT_CONFIG_LINE_STRING(var,org_var) \
	} else { \
		odd = (odd == 0) ? 1 : 0; \
		printf("<TR CLASS='%s'><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%s&nbsp;</TD><TD %s>&nbsp;", (odd == 0) ? "dataEven" : "dataOdd", \
		#org_var + 4, (strlen(org_var) == 0) ? "&lt;EMPTY&gt;" : html_encode(org_var, FALSE), (!strcmp(var, org_var)) ? "" : "CLASS='dataDiff'"); \
		if (strlen(var) == 0) { \
			printf("&lt;EMPTY&gt;"); \
		} else { \
			json_start = TRUE; \
			for (temp_ptr = strtok(var, ","); temp_ptr != NULL; temp_ptr = strtok(NULL, ",")) { \
				if (json_start == FALSE) \
					printf(", "); \
				json_start = FALSE; \
				printf("<A HREF='%s?type=contact%ss&item_name=%s'>%s</A>", CONFIG_CGI, (strstr(#org_var, "contactgroup")) ? "group" : "", \
				(!strcmp(temp_ptr, "*")) ? "" : url_encode(temp_ptr), html_encode(temp_ptr, FALSE)); \
			} \
		} \
		printf("&nbsp;</TD><TR>\n"); \
	}

	/** END MACRO declaration */


	if (content_type == JSON_CONTENT) {
		printf("\"cgi_config\": [\n");
	} else if (content_type == CSV_CONTENT) {
		printf("%s配置选项名称%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s默认配置%s%s", csv_data_enclosure, csv_data_enclosure, csv_delimiter);
		printf("%s当前设置%s", csv_data_enclosure, csv_data_enclosure);
		printf("\n");
	} else {
		printf("<TABLE BORDER=0 CLASS='data' cellpadding=2>\n");
		printf("<TR><TH CLASS='data'>配置选项名称</TH><TH CLASS='data'>默认设置</TH><TH CLASS='data'>当前设置</TH></TR>\n");
	}


	/* print all supported config vars
	   some options are printed differently to represent the value which is set
	*/

	PRINT_CONFIG_LINE_STRING(action_url_target, org_action_url_target)
	PRINT_CONFIG_LINE_STRING(authorization_config_file, org_authorization_config_file)
	PRINT_CONFIG_LINE_AUTH(authorized_for_all_host_commands, org_authorized_for_all_host_commands)
	PRINT_CONFIG_LINE_AUTH(authorized_for_all_hosts, org_authorized_for_all_hosts)
	PRINT_CONFIG_LINE_AUTH(authorized_for_all_service_commands, org_authorized_for_all_service_commands)
	PRINT_CONFIG_LINE_AUTH(authorized_for_all_services, org_authorized_for_all_services)
	PRINT_CONFIG_LINE_AUTH(authorized_for_configuration_information, org_authorized_for_configuration_information)
	PRINT_CONFIG_LINE_AUTH(authorized_for_full_command_resolution, org_authorized_for_full_command_resolution)
	PRINT_CONFIG_LINE_AUTH(authorized_for_read_only, org_authorized_for_read_only)
	PRINT_CONFIG_LINE_AUTH(authorized_for_comments_read_only, org_authorized_for_comments_read_only)
	PRINT_CONFIG_LINE_AUTH(authorized_for_downtimes_read_only, org_authorized_for_downtimes_read_only)
	PRINT_CONFIG_LINE_AUTH(authorized_for_system_commands, org_authorized_for_system_commands)
	PRINT_CONFIG_LINE_AUTH(authorized_for_system_information, org_authorized_for_system_information)
	PRINT_CONFIG_LINE_AUTH(authorized_contactgroup_for_all_host_commands, org_authorized_contactgroup_for_all_host_commands)
	PRINT_CONFIG_LINE_AUTH(authorized_contactgroup_for_all_hosts, org_authorized_contactgroup_for_all_hosts)
	PRINT_CONFIG_LINE_AUTH(authorized_contactgroup_for_all_service_commands, org_authorized_contactgroup_for_all_service_commands)
	PRINT_CONFIG_LINE_AUTH(authorized_contactgroup_for_all_services, org_authorized_contactgroup_for_all_services)
	PRINT_CONFIG_LINE_AUTH(authorized_contactgroup_for_configuration_information, org_authorized_contactgroup_for_configuration_information)
	PRINT_CONFIG_LINE_AUTH(authorized_contactgroup_for_full_command_resolution, org_authorized_contactgroup_for_full_command_resolution)
	PRINT_CONFIG_LINE_AUTH(authorized_contactgroup_for_read_only, org_authorized_contactgroup_for_read_only)
	PRINT_CONFIG_LINE_AUTH(authorized_contactgroup_for_comments_read_only, org_authorized_contactgroup_for_comments_read_only)
	PRINT_CONFIG_LINE_AUTH(authorized_contactgroup_for_downtimes_read_only, org_authorized_contactgroup_for_downtimes_read_only)
	PRINT_CONFIG_LINE_AUTH(authorized_contactgroup_for_system_commands, org_authorized_contactgroup_for_system_commands)
	PRINT_CONFIG_LINE_AUTH(authorized_contactgroup_for_system_information, org_authorized_contactgroup_for_system_information)
	PRINT_CONFIG_LINE_INT(add_notif_num_hard, org_add_notif_num_hard, "int")
	PRINT_CONFIG_LINE_INT(add_notif_num_soft, org_add_notif_num_soft, "int")
	PRINT_CONFIG_LINE_INT(color_transparency_index_b, org_color_transparency_index_b, "int")
	PRINT_CONFIG_LINE_INT(color_transparency_index_g, org_color_transparency_index_g, "int")
	PRINT_CONFIG_LINE_INT(color_transparency_index_r, org_color_transparency_index_r, "int")
	PRINT_CONFIG_LINE_STRING(cgi_log_archive_path, org_cgi_log_archive_path)
	PRINT_CONFIG_LINE_STRING(cgi_log_file, org_cgi_log_file)

	// cgi_log_rotation_method
	if (content_type == JSON_CONTENT || content_type == CSV_CONTENT) {
		PRINT_CONFIG_LINE_INT(cgi_log_rotation_method, org_cgi_log_rotation_method, "int")
	} else {
		odd = (odd == 0) ? 1 : 0;
		printf("<TR CLASS='%s'><TD>&nbsp;%s&nbsp;</TD>", (odd == 0) ? "dataEven" : "dataOdd", "cgi_log_rotation_method");
		printf("<TD>&nbsp;%d (", org_cgi_log_rotation_method);
		if (org_cgi_log_rotation_method == LOG_ROTATION_HOURLY)       printf("每小时");
		else if (org_cgi_log_rotation_method == LOG_ROTATION_DAILY)   printf("每天");
		else if (org_cgi_log_rotation_method == LOG_ROTATION_WEEKLY)  printf("每周");
		else if (org_cgi_log_rotation_method == LOG_ROTATION_MONTHLY) printf("每月");
		else printf("无法回滚");
		printf(")&nbsp;</TD><TD %s>", (org_cgi_log_rotation_method != cgi_log_rotation_method) ? "CLASS='dataDiff'" : "");
		printf("&nbsp;%d (", cgi_log_rotation_method);
		if (cgi_log_rotation_method == LOG_ROTATION_HOURLY)       printf("每小时");
		else if (cgi_log_rotation_method == LOG_ROTATION_DAILY)   printf("每天");
		else if (cgi_log_rotation_method == LOG_ROTATION_WEEKLY)  printf("每周");
		else if (cgi_log_rotation_method == LOG_ROTATION_MONTHLY) printf("每月");
		else printf("无法回滚");
		printf(")&nbsp;</TD><TR>\n");
	}

	PRINT_CONFIG_LINE_STRING(csv_delimiter, org_csv_delimiter)
	PRINT_CONFIG_LINE_STRING(csv_data_enclosure, org_csv_data_enclosure)
	PRINT_CONFIG_LINE_STRING(default_user_name, org_default_user_name)
	PRINT_CONFIG_LINE_INT(default_downtime_duration, org_default_downtime_duration, "int")
	PRINT_CONFIG_LINE_INT(default_expiring_acknowledgement_duration, org_default_expiring_acknowledgement_duration, "int")
	PRINT_CONFIG_LINE_INT(display_status_totals, org_display_status_totals, "bool")

	// default_statusmap_layout
	if (content_type == JSON_CONTENT || content_type == CSV_CONTENT) {
		PRINT_CONFIG_LINE_INT(default_statusmap_layout_method, org_default_statusmap_layout, "int")
	} else {
		odd = (odd == 0) ? 1 : 0;
		printf("<TR CLASS='%s'><TD>&nbsp;%s&nbsp;</TD>", (odd == 0) ? "dataEven" : "dataOdd", "default_statusmap_layout");
		printf("<TD>&nbsp;%d (", org_default_statusmap_layout);
		if (org_default_statusmap_layout == 0)      printf("用户定义坐标");
		else if (org_default_statusmap_layout == 1) printf("深度分层");
		else if (org_default_statusmap_layout == 2) printf("折叠树状");
		else if (org_default_statusmap_layout == 3) printf("平衡树状");
		else if (org_default_statusmap_layout == 4) printf("圆形图");
		else if (org_default_statusmap_layout == 5) printf("圆形图(标记)");
		else printf("无效");
		printf(")&nbsp;</TD><TD %s>", (org_default_statusmap_layout != default_statusmap_layout_method) ? "CLASS='dataDiff'" : "");
		printf("&nbsp;%d (", default_statusmap_layout_method);
		if (default_statusmap_layout_method == 0)      printf("用户定义坐标");
		else if (default_statusmap_layout_method == 1) printf("深度分层");
		else if (default_statusmap_layout_method == 2) printf("折叠树状");
		else if (default_statusmap_layout_method == 3) printf("平衡树状");
		else if (default_statusmap_layout_method == 4) printf("圆形图");
		else if (default_statusmap_layout_method == 5) printf("圆形图(标记)");
		else printf("无效");
		printf(")&nbsp;</TD><TR>\n");
	}

	PRINT_CONFIG_LINE_INT(enable_splunk_integration, org_enable_splunk_integration, "bool")
	PRINT_CONFIG_LINE_INT(enforce_comments_on_actions, org_enforce_comments_on_actions, "bool")
	PRINT_CONFIG_LINE_INT(escape_html_tags, org_escape_html_tags, "bool")

	// extinfo_show_child_hosts
	if (content_type == JSON_CONTENT || content_type == CSV_CONTENT) {
		PRINT_CONFIG_LINE_INT(extinfo_show_child_hosts, org_extinfo_show_child_hosts, "int")
	} else {
		odd = (odd == 0) ? 1 : 0;
		printf("<TR CLASS='%s'><TD>&nbsp;%s&nbsp;</TD>", (odd == 0) ? "dataEven" : "dataOdd", "extinfo_show_child_hosts");
		printf("<TD>&nbsp;%d (", org_extinfo_show_child_hosts);
		if (org_extinfo_show_child_hosts == SHOW_CHILD_HOSTS_IMMEDIATE) printf("立即仅");
		else if (org_extinfo_show_child_hosts == SHOW_CHILD_HOSTS_ALL)  printf("所有");
		else printf("无");
		printf(")&nbsp;</TD><TD %s>", (org_extinfo_show_child_hosts != extinfo_show_child_hosts) ? "CLASS='dataDiff'" : "");
		printf("&nbsp;%d (", extinfo_show_child_hosts);
		if (extinfo_show_child_hosts == SHOW_CHILD_HOSTS_IMMEDIATE) printf("立即仅");
		else if (extinfo_show_child_hosts == SHOW_CHILD_HOSTS_ALL)  printf("所有");
		else printf("无");
		printf(")&nbsp;</TD><TR>\n");
	}

	// first_day_of_week
	if (content_type == JSON_CONTENT || content_type == CSV_CONTENT) {
		PRINT_CONFIG_LINE_INT(week_starts_on_monday, org_first_day_of_week, "int")
	} else {
		odd = (odd == 0) ? 1 : 0;
		printf("<TR CLASS='%s'><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%d (%s)&nbsp;</TD><TD %s>&nbsp;%d (%s)&nbsp;</TD><TR>\n", \
		       (odd == 0) ? "dataEven" : "dataOdd", "first_day_of_week" , org_first_day_of_week, (org_first_day_of_week > 0) ? "MONDAY" : "SUNDAY", \
		       (week_starts_on_monday != org_first_day_of_week) ? "CLASS='dataDiff'" : "" , week_starts_on_monday, (week_starts_on_monday == TRUE) ? "MONDAY" : "SUNDAY");
	}

	PRINT_CONFIG_LINE_INT(highlight_table_rows, org_highlight_table_rows, "bool")
	PRINT_CONFIG_LINE_STRING(host_down_sound, org_host_down_sound)
	PRINT_CONFIG_LINE_STRING(host_unreachable_sound, org_host_unreachable_sound)
	PRINT_CONFIG_LINE_STRING(http_charset, org_http_charset)
	PRINT_CONFIG_LINE_STRING(illegal_output_chars, org_illegal_macro_output_chars)
	PRINT_CONFIG_LINE_INT(lock_author_names, org_lock_author_names, "bool")
	PRINT_CONFIG_LINE_INT(lowercase_user_name, org_lowercase_user_name, "bool")
	PRINT_CONFIG_LINE_STRING(main_config_file, org_main_config_file)
	PRINT_CONFIG_LINE_STRING(nagios_check_command, org_nagios_check_command)
	PRINT_CONFIG_LINE_STRING(normal_sound, org_normal_sound)
	PRINT_CONFIG_LINE_STRING(notes_url_target, org_notes_url_target)
	PRINT_CONFIG_LINE_INT(persistent_ack_comments, org_persistent_ack_comments, "bool")
	PRINT_CONFIG_LINE_STRING(physical_html_path, org_physical_html_path)
	PRINT_CONFIG_LINE_INT(refresh_rate, org_refresh_rate, "int")

	// refresh_type
	if (content_type == JSON_CONTENT || content_type == CSV_CONTENT) {
		PRINT_CONFIG_LINE_INT(refresh_type, org_refresh_type,  "int")
	} else {
		odd = (odd == 0) ? 1 : 0;
		printf("<TR CLASS='%s'><TD>&nbsp;%s&nbsp;</TD><TD>&nbsp;%d (%s)&nbsp;</TD><TD %s>&nbsp;%d (%s)&nbsp;</TD><TR>\n", \
		       (odd == 0) ? "dataEven" : "dataOdd", "refresh_type" , org_refresh_type, (org_refresh_type > 0) ? "JAVASCRIPT_REFRESH" : "HTTPHEADER_REFRESH", \
		       (refresh_type != org_refresh_type) ? "CLASS='dataDiff'" : "" , refresh_type, (refresh_type > 0) ? "JAVASCRIPT_REFRESH" : "HTTPHEADER_REFRESH");
	}

	PRINT_CONFIG_LINE_INT(result_limit, org_result_limit, "int")
	PRINT_CONFIG_LINE_STRING(service_critical_sound, org_service_critical_sound)
	PRINT_CONFIG_LINE_STRING(service_unknown_sound, org_service_unknown_sound)
	PRINT_CONFIG_LINE_STRING(service_warning_sound, org_service_warning_sound)
	PRINT_CONFIG_LINE_INT(show_all_services_host_is_authorized_for, org_show_all_services_host_is_authorized_for, "bool")
	PRINT_CONFIG_LINE_INT(show_partial_hostgroups, org_show_partial_hostgroups, "bool")
	PRINT_CONFIG_LINE_INT(show_tac_header, org_show_tac_header, "bool")
	PRINT_CONFIG_LINE_INT(show_tac_header_pending, org_show_tac_header_pending, "bool")
	PRINT_CONFIG_LINE_INT(showlog_current_states, org_showlog_current_states, "bool")
	PRINT_CONFIG_LINE_INT(showlog_initial_states, org_showlog_initial_states, "bool")
	PRINT_CONFIG_LINE_STRING(splunk_url, org_splunk_url)
	PRINT_CONFIG_LINE_INT(status_show_long_plugin_output, org_status_show_long_plugin_output, "bool")
	PRINT_CONFIG_LINE_STRING(statusmap_background_image, org_statusmap_background_image)
	PRINT_CONFIG_LINE_INT(suppress_maintenance_downtime, org_suppress_maintenance_downtime, "bool")
	PRINT_CONFIG_LINE_INT(tab_friendly_titles, org_tab_friendly_titles, "bool")
	PRINT_CONFIG_LINE_INT(tac_show_only_hard_state, org_tac_show_only_hard_state, "bool")
	PRINT_CONFIG_LINE_STRING(url_html_path, org_url_html_path)
	PRINT_CONFIG_LINE_STRING(url_stylesheets_path, org_url_stylesheets_path)
	PRINT_CONFIG_LINE_INT(use_authentication, org_use_authentication, "bool")
	PRINT_CONFIG_LINE_INT(use_logging, org_use_logging, "bool")
	PRINT_CONFIG_LINE_INT(use_pending_states, org_use_pending_states, "bool")
	PRINT_CONFIG_LINE_INT(use_ssl_authentication, org_use_ssl_authentication, "bool")


	if (content_type != CSV_CONTENT && content_type != JSON_CONTENT)
		printf("</TABLE>\n");
	else if (content_type == JSON_CONTENT)
		printf("\n]\n");

	return;
}

char *hash_color(int i) {
	char c;

	/* This is actually optimized for MAX_COMMAND_ARGUMENTS==32 ... */

	if ((i % 32) < 16) {
		if ((i % 32) < 8) c = '7';
		else c = '4';
	} else {
		if ((i % 32) < 24) c = '6';
		else c = '5';
	}

	/* Computation for standard case */
	hashed_color[0] = '#';
	hashed_color[1] = hashed_color[2] = ((i % 2) ? c : '0');
	hashed_color[3] = hashed_color[4] = (((i / 2) % 2) ? c : '0');
	hashed_color[5] = hashed_color[6] = (((i / 4) % 2) ? c : '0');
	hashed_color[7] = '\0';

	/* Override shades of grey */
	if ((i % 8) == 7) hashed_color[1] = hashed_color[3] = '0';
	if ((i % 8) == 0) hashed_color[2] = hashed_color[3] = hashed_color[4] = hashed_color[6] = c;

	return(hashed_color);
}

void display_command_expansion(void) {
	command *temp_command;
	int odd = 0;
	char *bg_class = "";
	int i, j;
	char *c, *cc;
	char commandline[MAX_COMMAND_BUFFER];
	char commandline_pre_processed[MAX_COMMAND_BUFFER];
	char *command_args[MAX_COMMAND_ARGUMENTS];
	int arg_count[MAX_COMMAND_ARGUMENTS];
	int lead_space[MAX_COMMAND_ARGUMENTS];
	int trail_space[MAX_COMMAND_ARGUMENTS];
	/* for host and service targets */
	host *hst = NULL;
	service *svc = NULL;
	char *processed_command;

	/* show host and/or service related raw command */
	hst = find_host(host_name);
	svc = find_service(host_name, service_desc);
    
    if (hst != NULL && svc == NULL)
		printf("<P><DIV ALIGN=CENTER CLASS='dataTitle'>主机 '%s' 命令扩展</DIV></P>\n", host_name);
	else if (hst != NULL && svc != NULL)
		printf("<P><DIV ALIGN=CENTER CLASS='dataTitle'>主机 '%s' 上的服务 '%s' 命令扩展</DIV></P>\n", host_name, service_desc);
	else
        printf("<P><DIV ALIGN=CENTER CLASS='dataTitle'>命令扩展</DIV></P>\n");

	/* Parse to_expand into parts */
	for (i = 0; i < MAX_COMMAND_ARGUMENTS; i++) command_args[i] = NULL;
	for (i = 0, command_args[0] = cc = c = strdup(to_expand); c && ((*c) != '\0') && (i < MAX_COMMAND_ARGUMENTS); c++, cc++) {
		if ((*c) == '\\') c++;
		else if ((*c) == '!') {
			(*cc) = '\0';
			cc = c++;
			command_args[++i] = (c--);
		}
		(*cc) = (*c);
	}
	if ((*c) == '\0')(*cc) = '\0';
	/* Precompute indexes of dangling whitespace */
	for (i = 0; i < MAX_COMMAND_ARGUMENTS; i++) {
		for (cc = command_args[i], lead_space[i] = 0; cc && isspace(*cc); cc++, lead_space[i]++) ;
		trail_space[i] = 0;
		for (; cc && ((*cc) != '\0'); cc++) if (isspace(*cc)) trail_space[i]++;
			else trail_space[i] = 0;
	}

	printf("<TABLE BORDER=0 CLASS='data'>\n");
	printf("<TR><TH CLASS='data'>命令名称</TH><TH CLASS='data'>命令行</TH></TR>\n");

	if ((*to_expand) != '\0') {
		arg_count[0] = 0;

		printf("<TR CLASS='dataEven'><TD CLASS='dataEven'>扩展:</TD><TD CLASS='dataEven'>%s", escape_string(command_args[0]));
		for (i = 1; (i < MAX_COMMAND_ARGUMENTS) && command_args[i]; i++)
			printf("!<FONT\n   COLOR='%s'>%s</FONT>", hash_color(i), escape_string(command_args[i]));
		printf("\n</TD></TR>\n");

		/* check all commands */
		for (temp_command = command_list; temp_command != NULL; temp_command = temp_command->next) {

			if (!strcmp(temp_command->name, command_args[0])) {

				arg_count[0]++;

				if (odd) {
					odd = 0;
					bg_class = "dataEven";
				} else {
					odd = 1;
					bg_class = "dataOdd";
				}

				printf("<TR CLASS='%s'>\n", bg_class);

				printf("<TD CLASS='%s'><A NAME='%s'></A>%s</TD>\n", bg_class, url_encode(temp_command->name), html_encode(temp_command->name, FALSE));
				printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(temp_command->command_line, FALSE));

				printf("</TR>\n<TR CLASS='%s'>\n", bg_class);

				for (i = 1; i < MAX_COMMAND_ARGUMENTS; i++) arg_count[i] = 0;

				printf("<TD CLASS='%s' ALIGN='right'>-&gt;</TD>\n", bg_class);
				printf("<TD CLASS='%s'>", bg_class);
				strncpy(commandline, temp_command->command_line, MAX_COMMAND_BUFFER);
				commandline[MAX_COMMAND_BUFFER - 1] = '\0';
				for (c = commandline; c && (cc = strstr(c, "$"));) {
					(*(cc++)) = '\0';
					printf("%s", html_encode(c, FALSE));
					strcat(commandline_pre_processed, c);
					if ((*cc) == '$') {
						/* Escaped '$' */
						printf("<FONT COLOR='#444444'>$</FONT>");
						c = (++cc);
					} else if (strncmp("ARG", cc, 3)) {
						/* Non-$ARGn$ macro */
						c = strstr(cc, "$");
						if (c)(*(c++)) = '\0';
						printf("<FONT COLOR='#777777'>$%s%s</FONT>", html_encode(cc, FALSE), (c ? "$" : ""));
                        strcat(commandline_pre_processed,"$");
						strcat(commandline_pre_processed,cc);
						if (c) strcat(commandline_pre_processed,"$");
						if (!c) printf("<FONT COLOR='#FF0000'> (未正确终止)</FONT>");
					} else {
						/* $ARGn$ macro */
						for (c = (cc += 3); isdigit(*c); c++) ;
						if (((*c) == '\0') || ((*c) == '$')) {
							/* Index is numeric */
							i = atoi(cc);
							if ((i > 0) && (i <= MAX_COMMAND_ARGUMENTS)) {
								arg_count[i]++;
								if (command_args[i]) {
									if (*(command_args[i]) != '\0') {
										printf("<FONT COLOR='%s'><B>%s%s%s</B></FONT>",
											hash_color(i), ((lead_space[i] > 0) || (trail_space[i] > 0) ? "<U>&zwj;" : ""),
											escape_string(command_args[i]), ((lead_space[i] > 0) || (trail_space[i] > 0) ? "&zwj;</U>" : ""));
										strcat(commandline_pre_processed,command_args[i]);
                                        } else printf("<FONT COLOR='#0000FF'>(空)</FONT>");
                                    } else printf("<FONT COLOR='#0000FF'>(未指定)</FONT>");
							} else printf("<FONT COLOR='#FF0000'>(不是有效的 $ARGn$ 索引: %u)</FONT>", i);
							if ((*c) != '\0') c++;
							else printf("<FONT COLOR='#FF0000'> (未正确终止)</FONT>");
						} else {
							/* Syntax err in index */
							c = strstr(cc, "$");
							printf("<FONT COLOR='#FF0000'>(不是 $ARGn$ 索引: &quot;%s&quot;)</FONT>", html_encode(strtok(cc, "$"), FALSE));
							if (c) c++;
						}
					}
				}
				if (c) {
					printf("%s", html_encode(c, FALSE));
					strcat(commandline_pre_processed, c);
				}
				commandline_pre_processed[MAX_COMMAND_BUFFER - 1] = '\0';

				printf("</TD></TR>\n");

				for (i = 1; (i < MAX_COMMAND_ARGUMENTS) && (command_args[i]); i++) {
					if (arg_count[i] == 0) {
						printf("<TR CLASS='%s'><TD CLASS='%s' ALIGN='right'><FONT COLOR='#FF0000'>未使用:</FONT></TD>\n", bg_class, bg_class);
						printf("<TD CLASS='%s'>$ARG%u$=<FONT COLOR='%s'>%s%s%s</FONT></TD></TR>\n", bg_class, i, hash_color(i),
						       ((lead_space[i] > 0) || (trail_space[i] > 0) ? "<U>&zwj;" : ""), escape_string(command_args[i]),
						       ((lead_space[i] > 0) || (trail_space[i] > 0) ? "&zwj;</U>" : ""));
					} else if (arg_count[i] > 1) {
						printf("<TR CLASS='%s'><TD CLASS='%s' ALIGN='right'>使用 %u x:</TD>\n", bg_class, bg_class, i);
						printf("<TD CLASS='%s'>$ARG%u$=<FONT COLOR='%s'>%s%s%s</FONT></TD></TR>\n", bg_class, i, hash_color(i),
						       ((lead_space[i] > 0) || (trail_space[i] > 0) ? "<U>&zwj;" : ""), escape_string(command_args[i]),
						       ((lead_space[i] > 0) || (trail_space[i] > 0) ? "&zwj;</U>" : ""));
					}
					if ((lead_space[i] > 0) || (trail_space[i] > 0)) {
						printf("<TR CLASS='%s'><TD CLASS='%s' ALIGN='right'><FONT COLOR='#0000FF'>悬空空白符:</FONT></TD>\n", bg_class, bg_class);
						printf("<TD CLASS='%s'>$ARG%u$=<FONT COLOR='#0000FF'>", bg_class, i);
						for (c = command_args[i], j = 0; c && isspace(*c); c++, j++)
							if ((*c) == ' ')	printf("[SP]");
							else if ((*c) == '\f')	printf("[FF]");
							else if ((*c) == '\n')	printf("[LF]");
							else if ((*c) == '\r')	printf("[CR]");
							else if ((*c) == '\t')	printf("[HT]");
							else if ((*c) == '\v')	printf("[VT]");
							else			printf("[0x%x]", *c);
						printf("</FONT><FONT COLOR='%s'>", hash_color(i));
						for (; c && ((*c) != '\0') && (j < strlen(command_args[i]) - trail_space[i]); c++, j++) putchar(*c);
						printf("</FONT><FONT COLOR='#0000FF'>");
						for (; c && ((*c) != '\0'); c++)
							if ((*c) == ' ')	printf("[SP]");
							else if ((*c) == '\f')	printf("[FF]");
							else if ((*c) == '\n')	printf("[LF]");
							else if ((*c) == '\r')	printf("[CR]");
							else if ((*c) == '\t')	printf("[HT]");
							else if ((*c) == '\v')	printf("[VT]");
							else			printf("[0x%x]", *c);
						printf("</FONT></TD></TR>\n");
					}
				}

				/* host command */
				if (hst != NULL && svc == NULL && is_authorized_for_full_command_resolution(&current_authdata)) {
					grab_host_macros_r(mac, hst);
					process_macros_r(mac, commandline_pre_processed, &processed_command, 0);
					printf("<TD CLASS='%s'>原始命令行</TD>\n", bg_class);
					printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(processed_command, FALSE));
				}

				/* service command */
				if (hst != NULL && svc != NULL && is_authorized_for_full_command_resolution(&current_authdata)) {
					grab_host_macros_r(mac, hst);
					grab_service_macros_r(mac, svc);
					process_macros_r(mac, commandline_pre_processed, &processed_command, 0);
					printf("<TD CLASS='%s'>原始命令行</TD>\n", bg_class);
					printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(processed_command, FALSE));
				}

				/* only command expansion w/o hosts and services given */
				if (hst == NULL && svc == NULL && is_authorized_for_full_command_resolution(&current_authdata)) {
					process_macros_r(mac, commandline_pre_processed, &processed_command, 0);
					printf("<TD CLASS='%s'>原始命令行</TD>\n", bg_class);
					printf("<TD CLASS='%s'>%s</TD>\n", bg_class, html_encode(processed_command, FALSE));
				}

				printf("</TR>\n<TR CLASS='%s'>\n", bg_class);
			}

		}

		if (!arg_count[0]) {
			printf("<TR CLASS='dataOdd'><TD CLASS='dataOdd' ALIGN='right'><FONT\n");
			printf("COLOR='#FF0000'>错误:</FONT></TD><TD CLASS='dataOdd'><FONT COLOR='#FF0000'>No\n");
			printf("命令 &quot;%s&quot; 查找</FONT></TD></TR>\n", escape_string(command_args[0]));
		}
	}

    printf("<TR CLASS='dataEven'><TD CLASS='dataEven'>扩展:</TD><TD CLASS='dataEven'><FORM\n");
	printf("METHOD='GET' ACTION='%s'><INPUT TYPE='HIDDEN' NAME='type' VALUE='命令'>\n", CONFIG_CGI);
    
    if (hst != NULL)
		printf("<INPUT TYPE='HIDDEN' NAME='host' VALUE='%s'>\n", host_name);
	if (svc != NULL)
		printf("<INPUT TYPE='HIDDEN' NAME='service' VALUE='%s'>\n", service_desc);

	printf("<INPUT TYPE='text' NAME='expand' SIZE='100%%' VALUE='%s'>\n", escape_string(to_expand));
	printf("<INPUT TYPE='SUBMIT' VALUE='执行'></FORM></TD></TR>\n");

	printf("</TABLE>\n");

	return;
}

void display_options(void) {

	if (display_type != DISPLAY_NONE)
		printf("<tr><td align=left class='reportSelectSubTitle'>对象类型:</td></tr>\n");
	printf("<tr><td align=left class='reportSelectItem'>");
	printf("<select name='type'>\n");
	printf("<option value='hosts' %s>主机\n", (display_type == DISPLAY_HOSTS) ? "SELECTED" : "");
	printf("<option value='hostdependencies' %s>主机依赖\n", (display_type == DISPLAY_HOSTDEPENDENCIES) ? "SELECTED" : "");
	printf("<option value='hostescalations' %s>主机增强\n", (display_type == DISPLAY_HOSTESCALATIONS) ? "SELECTED" : "");
	printf("<option value='hostgroups' %s>主机组\n", (display_type == DISPLAY_HOSTGROUPS) ? "SELECTED" : "");
	printf("<option value='services' %s>服务\n", (display_type == DISPLAY_SERVICES) ? "SELECTED" : "");
	printf("<option value='servicegroups' %s>服务组\n", (display_type == DISPLAY_SERVICEGROUPS) ? "SELECTED" : "");
	printf("<option value='servicedependencies' %s>服务依赖\n", (display_type == DISPLAY_SERVICEDEPENDENCIES) ? "SELECTED" : "");
	printf("<option value='serviceescalations' %s>服务增强\n", (display_type == DISPLAY_SERVICEESCALATIONS) ? "SELECTED" : "");
	printf("<option value='contacts' %s>联系人\n", (display_type == DISPLAY_CONTACTS) ? "SELECTED" : "");
	printf("<option value='contactgroups' %s>联系人组\n", (display_type == DISPLAY_CONTACTGROUPS) ? "SELECTED" : "");
	printf("<option value='timeperiods' %s>时间范围\n", (display_type == DISPLAY_TIMEPERIODS) ? "SELECTED" : "");
	printf("<option value='modules' %s>模块\n", (display_type == DISPLAY_MODULES) ? "SELECTED" : "");
	printf("<option value='commands' %s>命令\n", (display_type == DISPLAY_COMMANDS) ? "SELECTED" : "");
	printf("<option value='command' %s>命令扩展\n", (display_type == DISPLAY_COMMAND_EXPANSION) ? "SELECTED" : "");
	printf("</select>\n");
	printf("</td></tr>\n");

	return;
}

void store_default_settings(void) {

	/* fill all NULL pointers with an empty string */
	action_url_target = (action_url_target == NULL) ? "" : action_url_target;
	authorization_config_file = (authorization_config_file == NULL) ? "" : authorization_config_file;
	authorized_for_all_host_commands = (authorized_for_all_host_commands == NULL) ? "" : authorized_for_all_host_commands;
	authorized_for_all_hosts = (authorized_for_all_hosts == NULL) ? "" : authorized_for_all_hosts;
	authorized_for_all_service_commands = (authorized_for_all_service_commands == NULL) ? "" : authorized_for_all_service_commands;
	authorized_for_all_services = (authorized_for_all_services == NULL) ? "" : authorized_for_all_services;
	authorized_for_configuration_information = (authorized_for_configuration_information == NULL) ? "" : authorized_for_configuration_information;
	authorized_for_full_command_resolution = (authorized_for_full_command_resolution == NULL) ? "" : authorized_for_full_command_resolution;
	authorized_for_read_only = (authorized_for_read_only == NULL) ? "" : authorized_for_read_only;
	authorized_for_comments_read_only = (authorized_for_comments_read_only == NULL) ? "" : authorized_for_comments_read_only;
	authorized_for_downtimes_read_only = (authorized_for_downtimes_read_only == NULL) ? "" : authorized_for_downtimes_read_only;
	authorized_for_system_commands = (authorized_for_system_commands == NULL) ? "" : authorized_for_system_commands;
	authorized_for_system_information = (authorized_for_system_information == NULL) ? "" : authorized_for_system_information;
	authorized_contactgroup_for_all_host_commands = (authorized_contactgroup_for_all_host_commands == NULL) ? "" : authorized_contactgroup_for_all_host_commands;
	authorized_contactgroup_for_all_hosts = (authorized_contactgroup_for_all_hosts == NULL) ? "" : authorized_contactgroup_for_all_hosts;
	authorized_contactgroup_for_all_service_commands = (authorized_contactgroup_for_all_service_commands == NULL) ? "" : authorized_contactgroup_for_all_service_commands;
	authorized_contactgroup_for_all_services = (authorized_contactgroup_for_all_services == NULL) ? "" : authorized_contactgroup_for_all_services;
	authorized_contactgroup_for_configuration_information = (authorized_contactgroup_for_configuration_information == NULL) ? "" : authorized_contactgroup_for_configuration_information;
	authorized_contactgroup_for_full_command_resolution = (authorized_contactgroup_for_full_command_resolution == NULL) ? "" : authorized_contactgroup_for_full_command_resolution;
	authorized_contactgroup_for_read_only = (authorized_contactgroup_for_read_only == NULL) ? "" : authorized_contactgroup_for_read_only;
	authorized_contactgroup_for_comments_read_only = (authorized_contactgroup_for_comments_read_only == NULL) ? "" : authorized_contactgroup_for_comments_read_only;
	authorized_contactgroup_for_downtimes_read_only = (authorized_contactgroup_for_downtimes_read_only == NULL) ? "" : authorized_contactgroup_for_downtimes_read_only;
	authorized_contactgroup_for_system_commands = (authorized_contactgroup_for_system_commands == NULL) ? "" : authorized_contactgroup_for_system_commands;
	authorized_contactgroup_for_system_information = (authorized_contactgroup_for_system_information == NULL) ? "" : authorized_contactgroup_for_system_information;
	csv_delimiter = (csv_delimiter == NULL) ? "" : csv_delimiter;
	csv_data_enclosure = (csv_data_enclosure == NULL) ? "" : csv_data_enclosure;
	default_user_name = (default_user_name == NULL) ? "" : default_user_name;
	host_down_sound = (host_down_sound == NULL) ? "" : host_down_sound;
	host_unreachable_sound = (host_unreachable_sound == NULL) ? "" : host_unreachable_sound;
	http_charset = (http_charset == NULL) ? "" : http_charset;
	illegal_output_chars = (illegal_output_chars == NULL) ? "" : illegal_output_chars;
	normal_sound = (normal_sound == NULL) ? "" : normal_sound;
	notes_url_target = (notes_url_target == NULL) ? "" : notes_url_target;
	service_critical_sound = (service_critical_sound == NULL) ? "" : service_critical_sound;
	service_unknown_sound = (service_unknown_sound == NULL) ? "" : service_unknown_sound;
	service_warning_sound = (service_warning_sound == NULL) ? "" : service_warning_sound;
	splunk_url = (splunk_url == NULL) ? "" : splunk_url;
	statusmap_background_image = (statusmap_background_image == NULL) ? "" : statusmap_background_image;

	/* copy vars to org_vars*/
	org_action_url_target = strdup(action_url_target);
	org_authorization_config_file = strdup(authorization_config_file);
	org_authorized_for_all_host_commands = strdup(authorized_for_all_host_commands);
	org_authorized_for_all_hosts = strdup(authorized_for_all_hosts);
	org_authorized_for_all_service_commands = strdup(authorized_for_all_service_commands);
	org_authorized_for_all_services = strdup(authorized_for_all_services);
	org_authorized_for_configuration_information = strdup(authorized_for_configuration_information);
	org_authorized_for_full_command_resolution = strdup(authorized_for_full_command_resolution);
	org_authorized_for_read_only = strdup(authorized_for_read_only);
	org_authorized_for_comments_read_only = strdup(authorized_for_comments_read_only);
	org_authorized_for_downtimes_read_only = strdup(authorized_for_downtimes_read_only);
	org_authorized_for_system_commands = strdup(authorized_for_system_commands);
	org_authorized_for_system_information = strdup(authorized_for_system_information);
	org_authorized_contactgroup_for_all_host_commands = strdup(authorized_contactgroup_for_all_host_commands);
	org_authorized_contactgroup_for_all_hosts = strdup(authorized_contactgroup_for_all_hosts);
	org_authorized_contactgroup_for_all_service_commands = strdup(authorized_contactgroup_for_all_service_commands);
	org_authorized_contactgroup_for_all_services = strdup(authorized_contactgroup_for_all_services);
	org_authorized_contactgroup_for_configuration_information = strdup(authorized_contactgroup_for_configuration_information);
	org_authorized_contactgroup_for_full_command_resolution = strdup(authorized_contactgroup_for_full_command_resolution);
	org_authorized_contactgroup_for_downtimes_read_only = strdup(authorized_contactgroup_for_downtimes_read_only);
	org_authorized_contactgroup_for_comments_read_only = strdup(authorized_contactgroup_for_comments_read_only);
	org_authorized_contactgroup_for_read_only = strdup(authorized_contactgroup_for_read_only);
	org_authorized_contactgroup_for_system_commands = strdup(authorized_contactgroup_for_system_commands);
	org_authorized_contactgroup_for_system_information = strdup(authorized_contactgroup_for_system_information);
	org_cgi_log_archive_path = strdup(cgi_log_archive_path);
	org_cgi_log_file = strdup(cgi_log_file);
	org_csv_data_enclosure = strdup(csv_data_enclosure);
	org_csv_delimiter = strdup(csv_delimiter);
	org_default_user_name = strdup(default_user_name);
	org_host_down_sound = strdup(host_down_sound);
	org_host_unreachable_sound = strdup(host_unreachable_sound);
	org_http_charset = strdup(http_charset);
	org_illegal_macro_output_chars = strdup(illegal_output_chars);
	org_main_config_file = strdup(main_config_file);
	org_nagios_check_command = strdup(nagios_check_command);
	org_normal_sound = strdup(normal_sound);
	org_notes_url_target = strdup(notes_url_target);
	org_physical_html_path = strdup(physical_html_path);
	org_service_critical_sound = strdup(service_critical_sound);
	org_service_unknown_sound = strdup(service_unknown_sound);
	org_service_warning_sound = strdup(service_warning_sound);
	org_splunk_url = strdup(splunk_url);
	org_statusmap_background_image = strdup(statusmap_background_image);
	org_url_html_path = strdup(url_html_path);
	org_url_stylesheets_path = strdup(url_stylesheets_path);

	org_add_notif_num_hard = add_notif_num_hard;
	org_add_notif_num_soft = add_notif_num_soft;
	org_color_transparency_index_b = color_transparency_index_b;
	org_color_transparency_index_g = color_transparency_index_g;
	org_color_transparency_index_r = color_transparency_index_r;
	org_cgi_log_rotation_method = org_cgi_log_rotation_method;
	org_default_downtime_duration = default_downtime_duration;
	org_default_expiring_acknowledgement_duration = default_expiring_acknowledgement_duration;
	org_display_status_totals = display_status_totals;
	org_default_statusmap_layout = default_statusmap_layout_method;
	org_enable_splunk_integration = enable_splunk_integration;
	org_enforce_comments_on_actions = enforce_comments_on_actions;
	org_escape_html_tags = escape_html_tags;
	org_extinfo_show_child_hosts = extinfo_show_child_hosts;
	org_first_day_of_week = week_starts_on_monday;
	org_highlight_table_rows = highlight_table_rows;
	org_lock_author_names = lock_author_names;
	org_lowercase_user_name = lowercase_user_name;
	org_persistent_ack_comments = persistent_ack_comments;
	org_refresh_rate = refresh_rate;
	org_refresh_type = refresh_type;
	org_result_limit = result_limit;
	org_show_tac_header = show_tac_header;
	org_show_tac_header_pending = show_tac_header_pending;
	org_showlog_current_states = showlog_current_states;
	org_showlog_initial_states = showlog_initial_states;
	org_status_show_long_plugin_output = status_show_long_plugin_output;
	org_suppress_maintenance_downtime = suppress_maintenance_downtime;
	org_tab_friendly_titles = tab_friendly_titles;
	org_tac_show_only_hard_state = tac_show_only_hard_state;
	org_use_authentication = use_authentication;
	org_use_authentication = use_authentication;
	org_use_logging = use_logging;
	org_use_ssl_authentication = use_ssl_authentication;
	org_show_all_services_host_is_authorized_for = show_all_services_host_is_authorized_for;
	org_show_partial_hostgroups = show_partial_hostgroups;
	org_use_pending_states = use_pending_states;
}
