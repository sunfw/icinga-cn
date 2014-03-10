/**************************************************************************
 *
 * CMD.C - Icinga Command CGI
 *
 * Copyright (c) 1999-2009 Ethan Galstad (egalstad@nagios.org)
 * Copyright (c) 2009-2013 Icinga Development Team (http://www.icinga.org)
 *
 * Last Modified: 08-08-2010
 *
 * License:
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
 *************************************************************************/

/** @file cmd.c
 *  @brief submits commands to Icinga command pipe
**/


#include "../include/config.h"
#include "../include/common.h"
#include "../include/objects.h"
#include "../include/comments.h"
#include "../include/downtime.h"
#include "../include/statusdata.h"

#include "../include/cgiutils.h"
#include "../include/cgiauth.h"
#include "../include/getcgi.h"

/** @name External vars
    @{ **/
extern const char *extcmd_get_name(int id);

extern char main_config_file[MAX_FILENAME_LENGTH];
extern char url_html_path[MAX_FILENAME_LENGTH];
extern char url_images_path[MAX_FILENAME_LENGTH];
extern char command_file[MAX_FILENAME_LENGTH];
extern char comment_file[MAX_FILENAME_LENGTH];

extern int  check_external_commands;
extern int  use_authentication;
extern int  lock_author_names;
extern int  persistent_ack_comments;
extern int  send_ack_notifications;
extern int  default_expiring_acknowledgement_duration;
extern int  set_expire_ack_by_default;
extern int  default_expiring_disabled_notifications_duration;

extern int  display_header;
extern int  daemon_check;

extern int enforce_comments_on_actions;
extern int date_format;
extern int use_logging;
extern int default_downtime_duration;

extern scheduled_downtime *scheduled_downtime_list;
extern comment *comment_list;
/** @} */

/** @name LIMITS
 @{**/
#define MAX_AUTHOR_LENGTH		64
#define MAX_COMMENT_LENGTH		1024
#define NUMBER_OF_STRUCTS		((MAX_CGI_INPUT_PAIRS*2)+100)		/**< Depends on amount of MAX_CGI_INPUT_PAIRS */
/** @}*/

/** @name ELEMET TEMPLATE TYPES
 @{**/
#define PRINT_COMMON_HEADER			1
#define PRINT_AUTHOR				2
#define PRINT_STICKY_ACK			3
#define PRINT_PERSISTENT			4
#define PRINT_SEND_NOTFICATION			5
#define PRINT_COMMENT_BOX			6
#define PRINT_NOTIFICATION_DELAY		7
#define PRINT_START_TIME			8
#define PRINT_END_TIME				9
#define PRINT_CHECK_TIME			10
#define PRINT_FORCE_CHECK			11
#define PRINT_CHECK_OUTPUT_BOX			12
#define PRINT_PERFORMANCE_DATA_BOX		13
#define PRINT_FIXED_FLEXIBLE_TYPE		14
#define PRINT_BROADCAST_NOTIFICATION		15
#define PRINT_FORCE_NOTIFICATION		16
#define PRINT_EXPIRE_ACKNOWLEDGEMENT		17
#define PRINT_EXPIRE_DISABLE_NOTIFICATIONS	18
/** @}*/

/** @name OBJECT LIST TYPES
 @{**/
#define PRINT_HOST_LIST				19
#define PRINT_SERVICE_LIST			20
#define PRINT_COMMENT_LIST			21
#define PRINT_DOWNTIME_LIST			22
/** @}*/

/** @brief host/service list structure
 *
 *  Struct to hold information of hosts and services for batch processing
**/
struct hostlist {
	char *host_name;
	char *description;
};

/** @brief error list structure
 *
 *  hold the errors we find during processing of @ref commit_command_data
**/
struct errorlist {
	char *message;
};


/** @name Internal vars
    @{ **/
char *host_name = "";				/**< requested host name */
char *hostgroup_name = "";			/**< requested hostgroup name */
char *servicegroup_name = "";			/**< requested servicegroup name */
char *service_desc = "";				/**< requested service name */
char *comment_author = "";			/**< submitted comment author */
char *comment_data = "";				/**< submitted comment data */
char *start_time_string = "";			/**< the requested start time */
char *end_time_string = "";			/**< the requested end time */

char help_text[MAX_INPUT_BUFFER] = "";		/**< help string */
char plugin_output[MAX_INPUT_BUFFER] = "";	/**< plugin output text for passive submitted check */
char performance_data[MAX_INPUT_BUFFER] = "";	/**< plugin performance data for passive submitted check */

int notification_delay = 0;			/**< delay for submitted notification in minutes */
int schedule_delay = 0;				/**< delay for sheduled actions in minutes (Icinga restart, Notfications enable/disable)
							!not implemented in GUI! */
int persistent_comment = FALSE;			/**< bool if omment should survive Icinga restart */
int sticky_ack = TRUE;				/**< bool to disable notifications until recover */
int send_notification = FALSE;			/**< bool sends a notification if service gets acknowledged */
int use_ack_end_time = FALSE;			/**< bool if expire acknowledgement is selected or not */
int use_disabled_notif_end_time = FALSE;	/**< bool if expire disabled notifications is selected or not */
int force_check = FALSE;			/**< bool if check should be forced */
int plugin_state = STATE_OK;			/**< plugin state for passive submitted check */
int affect_host_and_services = FALSE;		/**< bool if notifiactions or else affect all host and services */
int propagate_to_children = FALSE;		/**< bool if en/disable host notifications should propagated to children */
int fixed = FALSE;				/**< bool if downtime is fixed or flexible */
unsigned long duration = 0L;			/**< downtime duration */
unsigned long triggered_by = 0L;		/**< downtime id which triggers submited downtime */
int child_options = 0;				/**< if downtime should trigger child host downtimes */
int force_notification = 0;			/**< force a notification to be send out through event handler */
int broadcast_notification = 0;			/**< this options determines if notification should be broadcasted */

int command_type = CMD_NONE;			/**< the requested command ID */
int command_mode = CMDMODE_REQUEST;		/**< if command mode is request or commit */

time_t start_time = 0L;				/**< start time as unix timestamp */
time_t end_time = 0L;				/**< end time as unix timestamp */

int CGI_ID = CMD_CGI_ID;				/**< ID to identify the cgi for functions in cgiutils.c */

unsigned long attr = MODATTR_NONE;		/**< default modified_attributes */

authdata current_authdata;			/**< struct to hold current authentication data */

/** Initialize the struct */
struct hostlist commands[NUMBER_OF_STRUCTS];

/** initialze the error list */
struct errorlist error[NUMBER_OF_STRUCTS];

/** Hold IDs of comments and downtimes */
unsigned long multi_ids[NUMBER_OF_STRUCTS];

/** store the authentication status when data gets checked to submited */
short is_authorized[NUMBER_OF_STRUCTS];

/** store the result of each object which get submited */
short submit_result[NUMBER_OF_STRUCTS];
/** @} */


/** @brief Print form for all details to submit command
 *  @param [in] cmd ID of requested command
 *
 *  This function generates the form for the command with all requested
 *  host/services/downtimes/comments items. This is the first page you get
 *  when you submit a command.
**/
void request_command_data(int);

/** @brief submits the command data and checks for sanity
 *  @param [in] cmd ID of requested command
 *
 *  This function checks the submitted data (@ref request_command_data)
 *  for sanity. If everything is alright it passes the data to @ref commit_command.
**/
void commit_command_data(int);

/** @brief checks the authorization and passes the data to cmd_submitf
 *  @param [in] cmd ID of requested command
 *  @retval OK
 *  @retval ERROR
 *  @return success / fail
 *
 *  Here the command get formatted properly to be readable by icinga
 *  core. It passes the data to @c cmd_submitf .
**/
int commit_command(int);

/** @brief write the command to Icinga command pipe
 *  @param [in] cmd the formatted command string
 *  @retval OK
 *  @retval ERROR
 *  @return success / fail
 *
 *  This function actually writes the formatted string into Icinga command pipe.
 *  And if configured also to Icinga CGI log.
**/
int write_command_to_file(char *);

/** @brief strips out semicolons and newlines from comment data
 *  @param [in,out] buffer the stringt which should be cleaned
 *
 *  Converts semicolons, newline and carriage return to space.
**/
void clean_comment_data(char *);

/** @brief strips out semicolons and newlines from comment data
 *  @param [in] element ID of the element which should be printed
 *  @param [in] cmd ID of requested command
 *
 *  These are templates for the different form elements. Specify
 *  the element you want to print with element id.
**/
void print_form_element(int, int);

/** @brief print the list of affected objects
 *  @param [in] list_type ID of the item list which should be printed
 *
 *  Used to print the list of requested objects. Depending on the command
 *  you can specify the list (HOST/SERVICE/COMMENT/DOWNTIME).
**/
void print_object_list(int);

/** @brief print the mouseover box with help text
 *  @param [in] content string which should be printed as help box
 *
 *  This writes the mousover help box.
**/
void print_help_box(char *);

/** @brief checks start and end time and if start_time is before end_time
 *  @param [in] e the error element list
 *
 *  Checks if author or comment is empty. If so it adds an error to error list.
**/
void check_comment_sanity(int*);

/** @brief checks if comment and author are not empty strings
 *  @param [in] e the error element list
 *
 *  Checks the sanity of given start and end time. Checks if time is
 *  wrong or start_time is past end_time then if found an error it
 *  adds an error to error list.
**/
void check_time_sanity(int*);

/** @brief Parses the requested GET/POST variables
 *  @retval TRUE
 *  @retval FALSE
 *  @return wether parsing was successful or not
 *
 *  @n This function parses the request and set's the necessary variables
**/
int process_cgivars(void);


/** @brief Yes we need a main function **/
int main(void) {
	int result = OK;

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

	/* read environment var ICINGA_COMMAND_FILE */
	strcpy(command_file, get_cmd_file_location());

	/* This requires the date_format parameter in the main config file */
	if (strcmp(start_time_string, ""))
		string_to_time(start_time_string, &start_time);

	if (strcmp(end_time_string, ""))
		string_to_time(end_time_string, &end_time);


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


	document_header(CGI_ID, TRUE, "External Command Interface");

	/* get authentication information */
	get_authentication_information(&current_authdata);

	if (display_header == TRUE) {

		/* Giving credits to stop.png image source */
		printf("\n<!-- 图片 \"stop.png\" 来自于 \"http://fedoraproject.org/wiki/Template:Admon/caution\" -->\n\n");

		/* begin top table */
		printf("<table border=0 width=100%%>\n");
		printf("<tr>\n");

		/* left column of the first row */
		printf("<td align=left valign=top width=33%%>\n");
		display_info_table("额外命令接口", &current_authdata, daemon_check);
		printf("</td>\n");

		/* center column of the first row */
		printf("<td align=center valign=top width=33%%>\n");
		printf("</td>\n");

		/* right column of the first row */
		printf("<td align=right valign=bottom width=33%%>\n");
		printf("</td>\n");

		/* end of top table */
		printf("</tr>\n");
		printf("</table>\n");
	}

	/* if no command was specified... */
	if (command_type == CMD_NONE) {
		print_generic_error_message("错误：未指定命令!", NULL, 2);
	}

	/* if not authorized to perform commands*/
	else if (is_authorized_for_read_only(&current_authdata) == TRUE) {
		print_generic_error_message("错误: 很显然您没有权限执行任何命令!", NULL, 1);
	}

	/* if this is the first request for a command, present option */
	else if (command_mode == CMDMODE_REQUEST)
		request_command_data(command_type);

	/* the user wants to commit the command */
	else if (command_mode == CMDMODE_COMMIT)
		commit_command_data(command_type);

	document_footer(CGI_ID);

	/* free allocated memory */
	free_memory();
	free_object_data();

	return OK;
}

int process_cgivars(void) {
	char **variables;
	char *temp_buffer = NULL;
	int error = FALSE;
	int x;
	int z = 0;
	int sticky_ack_set = FALSE;		/* default is TRUE */

	variables = getcgivars();

	/* Process the variables */
	for (x = 0; variables[x] != NULL; x++) {

		/* do some basic length checking on the variable identifier to prevent buffer overflows */
		if (strlen(variables[x]) >= MAX_INPUT_BUFFER - 1)
			continue;

		/* we found the command type */
		else if (!strcmp(variables[x], "cmd_typ")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			command_type = atoi(variables[x]);
		}

                /* we found the attr */
                else if (!strcmp(variables[x], "attr")) {
                        x++;
                        if (variables[x] == NULL) {
                                error = TRUE;
                                break;
                        }

                        attr = strtoul(variables[x], NULL, 10);
                }

		/* we found the command mode */
		else if (!strcmp(variables[x], "cmd_mod")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			command_mode = atoi(variables[x]);
		}

		/* we found a comment id or a downtime id*/
		else if (!strcmp(variables[x], "com_id") || !strcmp(variables[x], "down_id")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			multi_ids[z] = strtoul(variables[x], NULL, 10);
			z++;
		}

		/* we found the notification delay */
		else if (!strcmp(variables[x], "not_dly")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			notification_delay = atoi(variables[x]);
		}

		/* we found the schedule delay */
		else if (!strcmp(variables[x], "sched_dly")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			schedule_delay = atoi(variables[x]);
		}

		/* we found the comment author */
		else if (!strcmp(variables[x], "com_author")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if ((comment_author = (char *)strdup(variables[x])) == NULL)
				comment_author = "";
			strip_html_brackets(comment_author);
		}

		/* we found the comment data */
		else if (!strcmp(variables[x], "com_data")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if ((comment_data = (char *)strdup(variables[x])) == NULL)
				comment_data = "";
			strip_html_brackets(comment_data);
		}

		/* we found the host name */
		else if (!strcmp(variables[x], "host")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if ((host_name = (char *)strdup(variables[x])) == NULL)
				host_name = "";
			else {
				strip_html_brackets(host_name);

				/* Store hostname in struct */
				commands[x].host_name = host_name;
			}
		}

		/* we found the hostgroup name */
		else if (!strcmp(variables[x], "hostgroup")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if ((hostgroup_name = (char *)strdup(variables[x])) == NULL)
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

			if ((service_desc = (char *)strdup(variables[x])) == NULL)
				service_desc = "";
			else {
				strip_html_brackets(service_desc);

				/* Store service description in struct */
				commands[(x-2)].description = service_desc;
			}
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
			else {
				strip_html_brackets(host_name);
				commands[x].host_name = host_name;
			}

			temp_buffer = strtok(NULL, "");

			if ((service_desc = (char *)strdup(temp_buffer)) == NULL)
				service_desc = "";
			else {
				strip_html_brackets(service_desc);
				commands[x].description = service_desc;
			}
		}

		/* we found the servicegroup name */
		else if (!strcmp(variables[x], "servicegroup")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if ((servicegroup_name = (char *)strdup(variables[x])) == NULL)
				servicegroup_name = "";
			strip_html_brackets(servicegroup_name);
		}

		/* we got the persistence option for a comment */
		else if (!strcmp(variables[x], "persistent"))
			persistent_comment = TRUE;

		/* we got the notification option for an acknowledgement */
		else if (!strcmp(variables[x], "send_notification"))
			send_notification = TRUE;

		/* we got the acknowledgement type */
		else if (!strcmp(variables[x], "sticky_ack"))
			sticky_ack_set = TRUE;

		/* we use the end_time as expire time */
		else if (!strcmp(variables[x], "use_ack_end_time"))
			use_ack_end_time = TRUE;

		/* we use the end_time as disabled notifcations expire time */
		else if (!strcmp(variables[x], "use_disabled_notif_end_time"))
			use_disabled_notif_end_time = TRUE;

		/* we got the service check force option */
		else if (!strcmp(variables[x], "force_check"))
			force_check = TRUE;

		/* we got the option to affect host and all its services */
		else if (!strcmp(variables[x], "ahas"))
			affect_host_and_services = TRUE;

		/* we got the option to propagate to child hosts */
		else if (!strcmp(variables[x], "ptc"))
			propagate_to_children = TRUE;

		/* we got the option for fixed downtime */
		else if (!strcmp(variables[x], "fixed")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			fixed = (atoi(variables[x]) > 0) ? TRUE : FALSE;
		}

		/* we got the triggered by downtime option */
		else if (!strcmp(variables[x], "trigger")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			triggered_by = strtoul(variables[x], NULL, 10);
		}

		/* we got the child options */
		else if (!strcmp(variables[x], "childoptions")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			child_options = atoi(variables[x]);
		}

		/* we found the plugin output */
		else if (!strcmp(variables[x], "plugin_output")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			/* protect against buffer overflows */
			if (strlen(variables[x]) >= MAX_INPUT_BUFFER - 1) {
				error = TRUE;
				break;
			} else
				strcpy(plugin_output, variables[x]);
		}

		/* we found the performance data */
		else if (!strcmp(variables[x], "performance_data")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			/* protect against buffer overflows */
			if (strlen(variables[x]) >= MAX_INPUT_BUFFER - 1) {
				error = TRUE;
				break;
			} else
				strcpy(performance_data, variables[x]);
		}

		/* we found the plugin state */
		else if (!strcmp(variables[x], "plugin_state")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			plugin_state = atoi(variables[x]);
		}

		/* we found the hour duration */
		else if (!strcmp(variables[x], "hours")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (atoi(variables[x]) < 0) {
				error = TRUE;
				break;
			}
			duration += (unsigned long)(atoi(variables[x]) * 3600);
		}

		/* we found the minute duration */
		else if (!strcmp(variables[x], "minutes")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			if (atoi(variables[x]) < 0) {
				error = TRUE;
				break;
			}
			duration += (unsigned long)(atoi(variables[x]) * 60);
		}

		/* we found the start time */
		else if (!strcmp(variables[x], "start_time")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			start_time_string = (char *)malloc(strlen(variables[x]) + 1);
			if (start_time_string == NULL)
				start_time_string = "";
			else
				strcpy(start_time_string, variables[x]);
		}

		/* we found the end time */
		else if (!strcmp(variables[x], "end_time")) {
			x++;
			if (variables[x] == NULL) {
				error = TRUE;
				break;
			}

			end_time_string = (char *)malloc(strlen(variables[x]) + 1);
			if (end_time_string == NULL)
				end_time_string = "";
			else
				strcpy(end_time_string, variables[x]);
		}

		/* we found the forced notification option */
		else if (!strcmp(variables[x], "force_notification"))
			force_notification = NOTIFICATION_OPTION_FORCED;

		/* we found the broadcast notification option */
		else if (!strcmp(variables[x], "broadcast_notification"))
			broadcast_notification = NOTIFICATION_OPTION_BROADCAST;

		/* we got the persistence option for a comment */
		else if (!strcmp(variables[x], "nodaemoncheck"))
			daemon_check = FALSE;

	}

	if (command_mode == CMDMODE_COMMIT) {
		sticky_ack = sticky_ack_set;
	}

	/* free memory allocated to the CGI variables */
	free_cgivars(variables);

	return error;
}

void print_object_list(int list_type) {
	hoststatus *temp_hoststatus = NULL;
	servicestatus *temp_servicestatus = NULL;
	int x = 0;
	int row_color = 0;
	int host_passive = FALSE;
	int service_passive = FALSE;


	printf("<tr><td colspan=\"2\">&nbsp;</td></tr>\n");
	printf("<tr class=\"sectionHeader\"><td colspan=\"2\" >受影响的</td></tr>\n");

	printf("<tr><td colspan=\"2\">\n");

	printf("<script language='javascript' type=\"text/javascript\">\nchecked=false;\n");
	printf("function checkAllBoxes() {\n"
		"	checked = (checked == false) ? true : false;\n"
		"	for (var i=0; i < %d; i++) {\n"
		"		var checkboxes = document.getElementById(\"cb_\" + i);\n"
		"		if (checkboxes != null ) { checkboxes.checked = checked; }\n"
		"	}\n"
		"}\n", NUMBER_OF_STRUCTS);
	printf("</script>\n");

	printf("<TABLE cellspacing='2' cellpadding='0' border='0' width='100%%'>\n");

	if (list_type == PRINT_SERVICE_LIST)
		printf("<tr class=\"objectTableHeader\"><td width=\"46%%\">主机</td><td width=\"46%%\">服务</td><td width='16'><input type='checkbox' onclick=\"checkAllBoxes();\" title=\"全部勾选\"></td></tr>\n");
	else if (list_type == PRINT_HOST_LIST)
		printf("<tr class=\"objectTableHeader\"><td colspan=\"2\" width=\"96%%\">主机</td><td width='16'><input type='checkbox' onclick=\"checkAllBoxes();\" title=\"全部勾选\"></td></tr>\n");
	else
		printf("<tr><td colspan=\"3\">&nbsp;</td></tr>\n");

	for (x = 0; x < NUMBER_OF_STRUCTS; x++) {

		if (list_type == PRINT_HOST_LIST || list_type == PRINT_SERVICE_LIST) {
			host_passive = FALSE;
			service_passive = FALSE;

			if (commands[x].host_name == NULL)
				continue;

			if (list_type == PRINT_SERVICE_LIST && commands[x].description == NULL)
				continue;

			if (strlen(commands[x].host_name) != 0 && (
				command_type == CMD_SCHEDULE_HOST_CHECK ||
				command_type == CMD_DISABLE_HOST_CHECK ||
				command_type == CMD_SCHEDULE_SVC_CHECK ||
				command_type == CMD_DISABLE_SVC_CHECK )) {
				if((temp_hoststatus = find_hoststatus(commands[x].host_name)) != NULL) {
					if (temp_hoststatus->checks_enabled == FALSE)
						host_passive = TRUE;
				}

				if (list_type == PRINT_SERVICE_LIST && strlen(commands[x].description) != 0 ) {
					if((temp_servicestatus = find_servicestatus(commands[x].host_name, commands[x].description)) != NULL) {
						if (temp_servicestatus->checks_enabled == FALSE)
							service_passive = TRUE;
					}
				}
			}

		} else {
			if (multi_ids[x] == FALSE)
				continue;
		}

		row_color = (row_color == 0) ? 1 : 0;

		printf("<tr class=\"status%s\"><td width=\"50%%\"", (row_color == 0) ? "Even" : "Odd ");
		if (list_type == PRINT_SERVICE_LIST) {
			/* hostname and service description are present */
			if (strlen(commands[x].host_name) != 0  && strlen(commands[x].description) != 0) {
				printf(">%s</td><td>%s",
					escape_string(commands[x].host_name), escape_string(commands[x].description)
				);
				if (service_passive == TRUE) {
					printf("<img src='%s%s' align=right border=0 style='padding-right:2px' alt='被动' title='被动服务'>",
						url_images_path, PASSIVE_ICON
					);
				}
                                printf("</td>\n");

				printf("<td align='center'><input type='checkbox' name='hostservice' id=\"cb_%d\" value='%s^%s' title=\"%s服务\" %s></td></tr>\n",
					x, escape_string(commands[x].host_name), escape_string(commands[x].description),
					(service_passive == FALSE) ? "主动" : "被动", (service_passive == FALSE) ? "checked" : "");
			} else {
				/* if hostname is empty print inputbox instead */
				if (!strcmp(commands[x].host_name, ""))
					printf("><INPUT TYPE='TEXT' NAME='host' SIZE=30></td>");
				else
					printf("><INPUT TYPE='HIDDEN' NAME='host' VALUE='%s'>%s</td>", escape_string(commands[x].host_name), escape_string(commands[x].host_name));
				/* if service description is empty print inputbox instead */
				if (!strcmp(commands[x].description, ""))
					printf("<td><INPUT TYPE='TEXT' NAME='service' SIZE=30></td>");
				else
					printf("<td><INPUT TYPE='HIDDEN' NAME='service' VALUE='%s'>%s</td>", escape_string(commands[x].description), escape_string(commands[x].description));

				printf("<td></td></tr>\n");
			}
		} else if (list_type == PRINT_HOST_LIST) {
			/* if hostname is empty print inputbox instead */
			if (!strcmp(commands[x].host_name, ""))
				printf(" style=\"font-weight:bold;\">主机:</td><td><INPUT TYPE='TEXT' NAME='host' SIZE=30></td><td></td></tr>\n");
			else {
				printf(" style=\"font-weight:bold;\">主机:</td><td>%s", escape_string(commands[x].host_name));
				if (host_passive == TRUE) {
					printf("<img src='%s%s' align=right border=0 style='padding-right:2px' alt='被动' title='被动服务'>",
						url_images_path, PASSIVE_ICON
					);
				}
                                printf("</td>\n");

				printf("<td align='center'><input type='checkbox' name='host' id=\"cb_%d\" value='%s' title=\"%s主机\" %s></td></tr>\n",
					x, escape_string(commands[x].host_name),
					(host_passive == FALSE) ? "主动" : "被动", (host_passive == FALSE) ? "checked" : ""
				);
			}
		} else if (list_type == PRINT_COMMENT_LIST) {
			printf(" style=\"font-weight:bold;\">注释ID:</td><td><INPUT TYPE='HIDDEN' NAME='com_id' VALUE='%lu'>%lu</td></tr>\n", multi_ids[x], multi_ids[x]);
		} else if (list_type == PRINT_DOWNTIME_LIST) {
			printf(" style=\"font-weight:bold;\">安排宕机ID:</td><td><INPUT TYPE='HIDDEN' NAME='down_id' VALUE='%lu'>%lu</td></tr>\n", multi_ids[x], multi_ids[x]);
		}
	}

	printf("</td><tr></table>\n</td></tr>\n");

	return;
}

void print_help_box(char *content) {

	printf("<img src='%s%s' onMouseOver=\"return tooltip('<table border=0 width=100%% height=100%%>", url_images_path, CONTEXT_HELP_ICON);
	printf("<tr><td>%s</td></tr>", content);
	printf("</table>', '&nbsp;&nbsp;&nbsp帮助', 'border:1, width:500, xoffset:-250, yoffset:25, bordercolor:#333399, title_padding:2px, titletextcolor:#FFFFFF, backcolor:#CCCCFF');\" onMouseOut=\"return hideTip()\"");
	printf(" BORDER=0>");
	return;
}

void print_form_element(int element, int cmd) {
	time_t t;
	int t_hour, t_min;
	char buffer[MAX_INPUT_BUFFER];

	switch (element) {

	case PRINT_COMMON_HEADER:
		printf("<tr><td COLSPAN=\"2\">&nbsp;</td></tr>\n");
		printf("<tr><td COLSPAN=\"2\" CLASS='sectionHeader'>通用数据</td></tr>\n");
		printf("<tr><td COLSPAN=\"2\">&nbsp;</td></tr>\n");
		break;

	case PRINT_AUTHOR:
		printf("<tr><td class=\"objectDescription descriptionleft\">编辑者(您的名字):</td><td align=\"left\">");
		if (lock_author_names == TRUE)
			printf("<INPUT TYPE='HIDDEN' NAME='com_author' VALUE='%s'>%s</td></tr>\n", escape_string(comment_author), escape_string(comment_author));
		else
			printf("<INPUT TYPE='INPUT' NAME='com_author' VALUE='%s'></td></tr>\n", escape_string(comment_author));
		break;

	case PRINT_COMMENT_BOX:

		strcpy(help_text, "如果您使用了其他管理员, 如果有更多的用户(包括您)在使用，您可能会发现关于主机/服务故障的有用共享信息. "
		       "因此请务必输入一个您操作的简要说明.");

		printf("<tr><td class=\"objectDescription descriptionleft\">注释:");
		print_help_box(help_text);
		printf("</td><td align=\"left\">");
		printf("<TEXTAREA ID=\"com_data\" NAME='com_data' COLS=25 ROWS=2 onkeyup=\"check_input();\">%s</TEXTAREA>", escape_string(comment_data));
		printf("<BR><DIV ID='com_data_error' class=\"inputError\" style=\"display:none;\">发送的注释数据不能为空</DIV>");
		printf("</td></tr>\n");
		break;

	case PRINT_CHECK_OUTPUT_BOX:

		snprintf(help_text, sizeof(help_text), "请填写准确的输出字符串,它将被发送到 %s", PROGRAM_NAME);
		help_text[sizeof(help_text)-1] = '\x0';

		printf("<tr><td class=\"objectDescription descriptionleft\">检查输出:");
		print_help_box(help_text);
		printf("</td><td align=\"left\">");
		printf("<TEXTAREA ID=\"plugin_output\" NAME='plugin_output' COLS=25 ROWS=2  onkeyup=\"check_input();\"></TEXTAREA>");
		printf("<BR><DIV ID='plugin_output_error' class=\"inputError\" style=\"display:none;\">发送的输出字符串不能为空</DIV>");
		printf("</td></tr>\n");
		break;

	case PRINT_PERFORMANCE_DATA_BOX:

		snprintf(help_text, sizeof(help_text), "请填写准确的性能数据字符串,它将被发送到%s", PROGRAM_NAME);
		help_text[sizeof(help_text)-1] = '\x0';

		printf("<tr><td class=\"objectDescription descriptionleft\">性能数据:");
		print_help_box(help_text);
		printf("</td><td align=\"left\">");
		printf("<TEXTAREA NAME='performance_data' COLS=25 ROWS=2></TEXTAREA></td></tr>\n");
		break;

	case PRINT_STICKY_ACK:

		strcpy(help_text, "如果您想禁用通知,直到确认主机/服务恢复,选中此选项.");

		printf("<tr><td class=\"objectDescription descriptionleft\">跟踪确认:");
		print_help_box(help_text);
		printf("</td><td align=\"left\">");
		printf("<INPUT TYPE='checkbox' NAME='sticky_ack' %s></td></tr>\n", (sticky_ack == TRUE) ? "CHECKED" : "");
		break;

	case PRINT_SEND_NOTFICATION:

		strcpy(help_text, "如果您不想将确认通知发送给合适的联系人, 取消此选项.");

		printf("<tr><td class=\"objectDescription descriptionleft\">发送通知:");
		print_help_box(help_text);
		printf("</td><td align=\"left\">");
		printf("<INPUT TYPE='checkbox' NAME='send_notification' %s></td></tr>\n", (send_ack_notifications == TRUE) ? "CHECKED" : "");
		break;

	case PRINT_PERSISTENT:

		if (cmd == CMD_ACKNOWLEDGE_HOST_PROBLEM || cmd == CMD_ACKNOWLEDGE_SVC_PROBLEM)
			strcpy(help_text, "一旦确认将被删除,如果您想保留注释,选中此复选框.");
		else {
			snprintf(help_text, sizeof(help_text), "如果您取消此选项,在下次%s重启时将自动删除注释.", PROGRAM_NAME);
			help_text[sizeof(help_text)-1] = '\x0';
		}
		printf("<tr><td class=\"objectDescription descriptionleft\">持续%s:", (cmd == CMD_ACKNOWLEDGE_HOST_PROBLEM || cmd == CMD_ACKNOWLEDGE_SVC_PROBLEM) ? " 注释" : "");
		print_help_box(help_text);
		printf("</td><td align=\"left\">");
		printf("<INPUT TYPE='checkbox' NAME='persistent' %s></td></tr>\n", (persistent_ack_comments == TRUE || cmd == CMD_ADD_HOST_COMMENT || cmd == CMD_ADD_SVC_COMMENT) ? "CHECKED" : "");
		break;

	case PRINT_NOTIFICATION_DELAY:

		strcpy(help_text, "如果在安排下一个通知发送之前,主机/服务状态发生变化,通知延迟将会被忽略.");

		printf("<tr><td class=\"objectDescription descriptionleft\">通知延迟(从现在开始):");
		print_help_box(help_text);
		printf("</td><td align=\"left\">");
		printf("<INPUT TYPE='TEXT' ID='not_dly' NAME='not_dly' VALUE='%d' SIZE=\"4\">", notification_delay);
		printf("<BR><DIV ID='not_dly_error' class=\"inputError\" style=\"display:none;\">通知延迟不能为零</DIV>");
		printf("</td></tr>\n");
		break;

	case PRINT_START_TIME:
	case PRINT_END_TIME:
	case PRINT_CHECK_TIME:
		time(&t);
		if (element == PRINT_END_TIME)
			t += (unsigned long)default_downtime_duration;
		get_time_string(&t, buffer, sizeof(buffer) - 1, SHORT_DATE_TIME);
		printf("<tr><td class=\"objectDescription descriptionleft\">");
		if (element == PRINT_START_TIME) {
			strcpy(help_text, "设置宕机开始的日期/时间.");
			printf("开始时间:");
		}else if (element == PRINT_END_TIME ){
			strcpy(help_text,"设置宕机结束的日期/时间.");
			printf("结束时间:");
		} else {
			strcpy(help_text, "当按照安排检查时,设置日期/时间.");
			printf("检查时间:");
		}
		print_help_box(help_text);
		printf("</td><td align=\"left\"><INPUT TYPE='TEXT' class='timepicker' NAME='%s_time' VALUE='%s' SIZE=\"25\"></td></tr>\n", (element == PRINT_END_TIME) ? "end" : "start", buffer);
		break;

	case PRINT_FIXED_FLEXIBLE_TYPE:
		default_downtime_duration = default_downtime_duration / 60;
		t_min = default_downtime_duration % 60;
		default_downtime_duration = default_downtime_duration - t_min;
		t_hour = (default_downtime_duration / 60) ;

		snprintf(help_text, sizeof(help_text), "如果您选择<i>固定</i>选项, 宕机将在您指定的开始和结束时间内有效. 如果您没有选择<i>固定</i> "
		         "选项, %s将视之为<i>可变</i>宕机.当主机发生宕机或无法访问/服务变为严重时,可变宕机开始(在您指定的开始和结束 "
		         "时间段的某个时候)和最后直到您输入的持续时间. 固定宕机无法应用持续时间段.", PROGRAM_NAME);
		help_text[sizeof(help_text)-1] = '\x0';

		printf("<tr><td class=\"objectDescription descriptionleft\">类型:");
		print_help_box(help_text);
		printf("</td><td align=\"left\">\n");

		printf("\t<SELECT ID=\"flexible_selection\" NAME='fixed' onChange=\"if (document.getElementById('flexible_selection').selectedIndex == 0) document.getElementById('fd_row').style.display = 'none'; else document.getElementById('fd_row').style.display = '';\">\n");
		printf("\t\t<OPTION VALUE=1\">固定</OPTION>\n");
		printf("\t\t<OPTION VALUE=0\">可变</OPTION>\n");
		printf("\t</SELECT>\n");

		snprintf(help_text, sizeof(help_text), "在这里输入宕机持续时间.在时间过期之后%s将自动删除宕机.", PROGRAM_NAME);
		help_text[sizeof(help_text)-1] = '\x0';

		printf("<tr id=\"fd_row\" style=\"display:none;\"><td class=\"objectDescription descriptionleft\">可变持续时间:");
		print_help_box(help_text);
		printf("</td><td align=\"left\">\n");
		printf("\t<table border=0  cellspacing=0 cellpadding=0>\n");
		printf("\t\t<tr>\n");
		printf("\t\t\t<td><INPUT TYPE='TEXT' NAME='hours' VALUE='%d' SIZE=4 MAXLENGTH=4></td>\n", t_hour);
		printf("\t\t\t<td width=\"50\">&nbsp;小时</td>\n");
		printf("\t\t\t<td><INPUT TYPE='TEXT' NAME='minutes' VALUE='%d' SIZE=2 MAXLENGTH=2></td>\n", t_min);
		printf("\t\t\t<td width=\"50\">&nbsp;分钟</td>\n");
		printf("\t\t</tr>\n");
		printf("\t</table>\n");
		printf("</td></tr>\n");
		break;

	case PRINT_EXPIRE_ACKNOWLEDGEMENT:

		strcpy(help_text, "如果你想让确认逾期, 选择此选项.");

		printf("<tr><td class=\"objectDescription descriptionleft\">使用逾期时间:");
		print_help_box(help_text);
		printf("</td><td align=\"left\">");
		printf("<INPUT TYPE='checkbox' ID='expire_checkbox' NAME='use_ack_end_time' onClick=\"if (document.getElementById('expire_checkbox').checked == true) document.getElementById('expired_date_row').style.display = ''; else document.getElementById('expired_date_row').style.display = 'none';\" %s></td></tr>\n", (set_expire_ack_by_default == TRUE) ? "CHECKED" : "");

		snprintf(help_text, sizeof(help_text), "在这里输入此确认的逾期日期/时间. 在逾期时间过后,%s会自动删除确认.", PROGRAM_NAME);
		help_text[sizeof(help_text)-1] = '\x0';

		time(&t);
		t += (unsigned long)default_expiring_acknowledgement_duration;
		get_time_string(&t, buffer, sizeof(buffer) - 1, SHORT_DATE_TIME);

		printf("<tr id=\"expired_date_row\" style=\"display:%s;\"><td class=\"objectDescription descriptionleft\">逾期时间:", (set_expire_ack_by_default == TRUE) ? "" : "none");
		print_help_box(help_text);
		printf("</td><td align=\"left\"><INPUT TYPE='TEXT' class='timepicker' NAME='end_time' VALUE='%s' SIZE=\"25\"></td></tr>\n", buffer);
		break;

        case PRINT_EXPIRE_DISABLE_NOTIFICATIONS:

                strcpy(help_text, "如果你想要禁用通知逾期, 选中此选项.");

                printf("<tr><td class=\"objectDescription descriptionleft\">使用逾期时间:");
                print_help_box(help_text);
                printf("</td><td align=\"left\">");
                printf("<INPUT TYPE='checkbox' ID='expire_checkbox' NAME='use_disabled_notif_end_time' onClick=\"if (document.getElementById('expire_checkbox').checked == true) document.getElementById('expired_date_row').style.display = ''; else document.getElementById('expired_date_row').style.display = 'none';\"></td></tr>\n");

                snprintf(help_text, sizeof(help_text), "输入禁用通知的逾期日期/时间. %s将在此时间逾期后自动重新启用所有通知.", PROGRAM_NAME);
                help_text[sizeof(help_text)-1] = '\x0';

                time(&t);
                t += (unsigned long)default_expiring_disabled_notifications_duration;
                get_time_string(&t, buffer, sizeof(buffer) - 1, SHORT_DATE_TIME);

                printf("<tr id=\"expired_date_row\" style=\"display:none;\"><td class=\"objectDescription descriptionleft\">逾期时间:");
                print_help_box(help_text);
                printf("</td><td align=\"left\"><INPUT TYPE='TEXT' class='timepicker' NAME='end_time' VALUE='%s' SIZE=\"25\"></td></tr>\n", buffer);
                break;

	case PRINT_FORCE_CHECK:

		snprintf(help_text, sizeof(help_text), "如果您选择此项, 无论安排什么时间执行检查和主机/服务是否启用检查,%s都将强制主机/服务检查.", PROGRAM_NAME);
		help_text[sizeof(help_text)-1] = '\x0';

		printf("<tr><td class=\"objectDescription descriptionleft\">强制检查:");
		print_help_box(help_text);
		printf("</td><td align=\"left\">");
		printf("<INPUT TYPE='checkbox' NAME='force_check' %s></td></tr>\n", (force_check == TRUE) ? "CHECKED" : "");
		break;

	case PRINT_BROADCAST_NOTIFICATION:

		strcpy(help_text, "选择此选项会导致发送通知到所有正常(非增强)和增强联系人.如果您需要收到一个重要消息,这些选项允许您覆盖正常的通知逻辑.");

		printf("<tr><td class=\"objectDescription descriptionleft\">广播:");
		print_help_box(help_text);
		printf("</td><td align=\"left\">");
		printf("<INPUT TYPE='checkbox' NAME='broadcast_notification'></td></tr>\n");
		break;

	case PRINT_FORCE_NOTIFICATION:

		snprintf(help_text, sizeof(help_text), "在%s中自定义通知通常遵循通知逻辑.选择此选项将强制发送通知,不分时间限制,无论是否启用通知等.", PROGRAM_NAME);
		help_text[sizeof(help_text)-1] = '\x0';

		printf("<tr><td class=\"objectDescription descriptionleft\">强制:");
		print_help_box(help_text);
		printf("</td><td align=\"left\">");
		printf("<INPUT TYPE='checkbox' NAME='force_notification'></td></tr>\n");
		break;

	default:
		break;
	}

	return;
}

void request_command_data(int cmd) {
	char start_time[MAX_DATETIME_LENGTH];
	contact *temp_contact;
	scheduled_downtime *temp_downtime;
	host *temp_host = NULL;
	char action[MAX_INPUT_BUFFER];
	int found_trigger_objects = FALSE;

	/* get default name to use for comment author */
	temp_contact = find_contact(current_authdata.username);
	if (temp_contact != NULL && temp_contact->alias != NULL)
		comment_author = temp_contact->alias;
	else
		comment_author = current_authdata.username;

	printf("<BR>");

	switch (cmd) {

	case CMD_ADD_HOST_COMMENT:
	case CMD_ADD_SVC_COMMENT:
		snprintf(action, sizeof(action), "添加%s注释", (cmd == CMD_ADD_HOST_COMMENT) ? "主机" : "服务");
		break;

	case CMD_DEL_HOST_COMMENT:
	case CMD_DEL_SVC_COMMENT:
		snprintf(action, sizeof(action), "删除%s注释", (cmd == CMD_DEL_HOST_COMMENT) ? "主机" : "服务");
		break;

	case CMD_DELAY_HOST_NOTIFICATION:
	case CMD_DELAY_SVC_NOTIFICATION:
		snprintf(help_text, sizeof(help_text), "该命令用于延迟发出对指定%s的故障通知.如果在安排下一个通知发出之前，%s状态发生变化, "
		         "通知延迟将被忽略.如果%s当前是%s,该命令无意义.", (cmd == CMD_DELAY_HOST_NOTIFICATION) ? "主机" : "服务", (cmd == CMD_DELAY_HOST_NOTIFICATION) ? "主机" : "服务", (cmd == CMD_DELAY_HOST_NOTIFICATION) ? "主机" : "服务", (cmd == CMD_DELAY_HOST_NOTIFICATION) ? "运行":"在一个正常状态下");
		snprintf(action, sizeof(action), "延迟%s忽略", (cmd == CMD_DELAY_HOST_NOTIFICATION) ? "主机" : "服务");
		break;

	case CMD_SCHEDULE_HOST_CHECK:
	case CMD_SCHEDULE_SVC_CHECK:
		snprintf(help_text, sizeof(help_text), "该命令是用于安排下一次对%s检查. %s将在指定时间内重新排队检查%s.", (cmd == CMD_SCHEDULE_HOST_CHECK) ? "主机" : "服务", PROGRAM_NAME, (cmd == CMD_SCHEDULE_HOST_CHECK) ? "主机" : "服务e");
		snprintf(action, sizeof(action), "安排%s检查", (cmd == CMD_SCHEDULE_HOST_CHECK) ? "主机" : "服务");
		break;

	case CMD_ENABLE_SVC_CHECK:
	case CMD_DISABLE_SVC_CHECK:
		snprintf(action, sizeof(action), "在方案基础上%s主动服务检查", (cmd == CMD_ENABLE_SVC_CHECK) ? "启用" : "禁用");
		break;

	case CMD_ENABLE_NOTIFICATIONS:
	case CMD_DISABLE_NOTIFICATIONS:
		snprintf(help_text, sizeof(help_text), "在方案基础上此命令用于%s主机和服务的通知", (cmd == CMD_ENABLE_NOTIFICATIONS) ? "启用" : "禁用");
		snprintf(action, sizeof(action), "在方案基础上%s通知", (cmd == CMD_ENABLE_NOTIFICATIONS) ? "启用" : "禁用");
		break;

	case CMD_DISABLE_NOTIFICATIONS_EXPIRE_TIME:
		snprintf(help_text, sizeof(help_text), "在方案基础上,此命令用于使用逾期时间禁用主机和服务通知");
		snprintf(action, sizeof(action), "在方案基础上使用逾期时间禁用通知, ");
		break;

	case CMD_SHUTDOWN_PROCESS:
	case CMD_RESTART_PROCESS:
		snprintf(action, sizeof(action), "%s%s进程", (cmd == CMD_SHUTDOWN_PROCESS) ? "关闭" : "重启", PROGRAM_NAME);
		break;

	case CMD_ENABLE_HOST_SVC_CHECKS:
	case CMD_DISABLE_HOST_SVC_CHECKS:
		if (cmd == CMD_ENABLE_HOST_SVC_CHECKS)
			snprintf(help_text, sizeof(help_text), "该命令用于启用与指定主机相关的所有服务的主动检查");
		else {
			snprintf(help_text, sizeof(help_text), "该命令用于禁用与指定主机相关的所有服务的主动检查. "
			         "当禁用服务时,%s不会监视服务.当禁用指定服务时,可以"
			         "阻止发送给指定服务的任何通知. 为了%s检查服务,你以后将不得不重启服务. "
			         "禁用服务检查未必能阻止发送关于主机与那些相关服务的通知.", PROGRAM_NAME, PROGRAM_NAME);
		}
		snprintf(action, sizeof(action), "%s这些主机上所有服务的主动检查", (cmd == CMD_ENABLE_HOST_SVC_CHECKS) ? "启用" : "禁用");
		break;

	case CMD_SCHEDULE_HOST_SVC_CHECKS:
		snprintf(action, sizeof(action), "安排这些主机所有服务的检查");
		break;

	case CMD_DEL_ALL_HOST_COMMENTS:
	case CMD_DEL_ALL_SVC_COMMENTS:
		snprintf(action, sizeof(action), "删除这些%s所有注释", (cmd == CMD_DEL_ALL_HOST_COMMENTS) ? "主机" : "服务");
		break;

	case CMD_ENABLE_SVC_NOTIFICATIONS:
	case CMD_DISABLE_SVC_NOTIFICATIONS:
		snprintf(action, sizeof(action), "%s这些服务的通知", (cmd == CMD_ENABLE_SVC_NOTIFICATIONS) ? "启用" : "禁用");
		break;

	case CMD_ENABLE_HOST_NOTIFICATIONS:
	case CMD_DISABLE_HOST_NOTIFICATIONS:
		snprintf(action, sizeof(action), "%s这些主机的通知", (cmd == CMD_ENABLE_HOST_NOTIFICATIONS) ? "启用" : "禁用");
		break;

	case CMD_ENABLE_ALL_NOTIFICATIONS_BEYOND_HOST:
	case CMD_DISABLE_ALL_NOTIFICATIONS_BEYOND_HOST:
		snprintf(help_text, sizeof(help_text), "该命令用于%s位于指定主机<i>以外</i>的所有主机和服务的通知(从%s的视图).", (cmd == CMD_ENABLE_ALL_NOTIFICATIONS_BEYOND_HOST) ? "启用" : "禁用", PROGRAM_NAME);
		snprintf(action, sizeof(action), "%s这些主机以外的所有主机和服务的通知", (cmd == CMD_ENABLE_ALL_NOTIFICATIONS_BEYOND_HOST) ? "启用" : "禁用");
		break;

	case CMD_ENABLE_HOST_SVC_NOTIFICATIONS:
	case CMD_DISABLE_HOST_SVC_NOTIFICATIONS:
		snprintf(action, sizeof(action), "%s这些主机的所有服务通知", (cmd == CMD_ENABLE_HOST_SVC_NOTIFICATIONS) ? "启用" : "禁用");
		break;

	case CMD_ACKNOWLEDGE_HOST_PROBLEM:
	case CMD_ACKNOWLEDGE_SVC_PROBLEM:
		snprintf(action, sizeof(action), "确认%s故障", (cmd == CMD_ACKNOWLEDGE_HOST_PROBLEM) ? "主机" : "服务");
		break;

	case CMD_START_EXECUTING_HOST_CHECKS:
	case CMD_STOP_EXECUTING_HOST_CHECKS:
		snprintf(action, sizeof(action), "在方案基础上%s执行主机检查", (cmd == CMD_START_EXECUTING_HOST_CHECKS) ? "开始" : "停止");
		break;

	case CMD_START_EXECUTING_SVC_CHECKS:
	case CMD_STOP_EXECUTING_SVC_CHECKS:
		if (cmd == CMD_START_EXECUTING_SVC_CHECKS)
			snprintf(help_text, sizeof(help_text), "该命令用于在方案基础上主动服务检查的恢复执行.依旧不会检查个别禁用的服务.");
		else
			snprintf(help_text, sizeof(help_text), "该命令用于暂时停止%s主动执行的任何服务检查.这样将有阻止发送任何通知的副作用(任何及所有服务和主机)."
                     "不再次执行服务检查直到您发出命令恢复服务检查执行. ", PROGRAM_NAME);
		snprintf(action, sizeof(action), "%s执行主动服务检查", (cmd == CMD_START_EXECUTING_SVC_CHECKS) ? "开始" : "停止");
		break;

	case CMD_START_ACCEPTING_PASSIVE_SVC_CHECKS:
	case CMD_STOP_ACCEPTING_PASSIVE_SVC_CHECKS:
		snprintf(help_text, sizeof(help_text), "该命令用于使%s %s接受在额外命令文件查找的被动服务检查结果.", PROGRAM_NAME, (cmd == CMD_START_ACCEPTING_PASSIVE_SVC_CHECKS) ? "开始" : "停止");
		snprintf(action, sizeof(action), "在方案基础上%s接受被动服务检查", (cmd == CMD_START_ACCEPTING_PASSIVE_SVC_CHECKS) ? "开始" : "停止");
		break;

	case CMD_ENABLE_PASSIVE_SVC_CHECKS:
	case CMD_DISABLE_PASSIVE_SVC_CHECKS:
		if (cmd == CMD_ENABLE_PASSIVE_SVC_CHECKS)
			snprintf(help_text, sizeof(help_text), "该命令用于允许%s接受在特定服务的额外命令文件查找的被动服务检查结果.", PROGRAM_NAME);
		else
			snprintf(help_text, sizeof(help_text), "该命令用于停止%s接受在特定服务的额外命令文件查找的被动服务检查结果. 查找的所有被动服务检查结果忽略该服务.", PROGRAM_NAME);
		snprintf(action, sizeof(action), "%s接受这些服务被动服务检查结果", (cmd == CMD_ENABLE_PASSIVE_SVC_CHECKS) ? "开始" : "停止");
		break;

	case CMD_ENABLE_EVENT_HANDLERS:
	case CMD_DISABLE_EVENT_HANDLERS:
		if (cmd == CMD_ENABLE_EVENT_HANDLERS)
			snprintf(help_text, sizeof(help_text), "该命令用于允许%s运行主机和服务事件处理程.", PROGRAM_NAME);
		else
			snprintf(help_text, sizeof(help_text), "该命令用于暂时阻止%s运行任何主机或服务的事件处理程序.", PROGRAM_NAME);
		snprintf(action, sizeof(action), "在方案基础上%s事件处理程序", (cmd == CMD_ENABLE_EVENT_HANDLERS) ? "启用" : "禁用");
		break;

	case CMD_ENABLE_HOST_EVENT_HANDLER:
	case CMD_DISABLE_HOST_EVENT_HANDLER:
		snprintf(help_text, sizeof(help_text), "该命令用于%s所选的主机事件处理程序", (cmd == CMD_ENABLE_HOST_EVENT_HANDLER) ? "启用" : "禁用");
		snprintf(action, sizeof(action), "%s这些主机的事件处理程序", (cmd == CMD_ENABLE_HOST_EVENT_HANDLER) ? "启用" : "禁用");
		break;

	case CMD_ENABLE_SVC_EVENT_HANDLER:
	case CMD_DISABLE_SVC_EVENT_HANDLER:
		snprintf(help_text, sizeof(help_text), "该命令用于%s所选的服务事件处理程序", (cmd == CMD_ENABLE_SVC_EVENT_HANDLER) ? "启用" : "禁用");
		snprintf(action, sizeof(action), "%s这些服务的事件处理程序", (cmd == CMD_ENABLE_SVC_EVENT_HANDLER) ? "启用" : "禁用");
		break;

	case CMD_ENABLE_HOST_CHECK:
        case CMD_DISABLE_HOST_CHECK:
            if (cmd==CMD_DISABLE_HOST_CHECK)
                snprintf(help_text,sizeof(help_text),"该命令用于暂时阻止%s主动检查特定主机的状态.如果%s需要检查该主机的状态,假设与禁用检查之前的状态相同.", PROGRAM_NAME, PROGRAM_NAME);
            snprintf(action,sizeof(action),"%s主动主机检查",(cmd==CMD_ENABLE_HOST_CHECK)?"启用" : "禁用");
            break;
			
        case CMD_STOP_OBSESSING_OVER_SVC_CHECKS:
        case CMD_START_OBSESSING_OVER_SVC_CHECKS:
            if (cmd==CMD_START_OBSESSING_OVER_SVC_CHECKS)
                snprintf(help_text,sizeof(help_text),"该命令用于%s强迫开始服务检查.阅读文档关于分布式监控的更多信息.", PROGRAM_NAME);
            snprintf(action,sizeof(action),"在方案基础上强迫%s服务检查",(cmd==CMD_STOP_OBSESSING_OVER_SVC_CHECKS)?"停止":"开始");
            break;
			
        case CMD_REMOVE_HOST_ACKNOWLEDGEMENT:
        case CMD_REMOVE_SVC_ACKNOWLEDGEMENT:
            snprintf(help_text,sizeof(help_text),"该命令用于删除%s故障确认. 一旦确认被删除, 通知可以开始"
                     "发送关于%s故障.",(cmd==CMD_REMOVE_HOST_ACKNOWLEDGEMENT)?"主机" : "服务",(cmd==CMD_REMOVE_HOST_ACKNOWLEDGEMENT)?"主机" : "服务");
            snprintf(action,sizeof(action),"删除%s确认",(cmd==CMD_REMOVE_HOST_ACKNOWLEDGEMENT)?"主机" : "服务");
            break;
			
        case CMD_SCHEDULE_HOST_DOWNTIME:
        case CMD_SCHEDULE_SVC_DOWNTIME:
            snprintf(help_text,sizeof(help_text),"该命令用于这些%s的宕机安排.在指定的宕机期间, %s将不会发送关于%s的通知. "
                     "当宕机安排到期时, 通常%s会将通知发送给%s.保留宕机安排"
                     "通过计划关闭和重启.",(cmd==CMD_SCHEDULE_HOST_DOWNTIME)?"主机" : "服务",PROGRAM_NAME,(cmd==CMD_SCHEDULE_HOST_DOWNTIME)?"主机" : "服务",PROGRAM_NAME,(cmd==CMD_SCHEDULE_HOST_DOWNTIME)?"主机" : "服务");
            snprintf(action,sizeof(action),"这些%s的宕机安排",(cmd==CMD_SCHEDULE_HOST_DOWNTIME)?"主机" : "服务");
            break;

	case CMD_DEL_DOWNTIME_BY_HOST_NAME:
                snprintf(help_text, sizeof(help_text), "此命令是用来删除所有已经提供主机名的并已指定主机和其所有服务的宕机时间.");
		snprintf(action, sizeof(action), "删除这些主机和主机自身所有服务的宕机时间");
                break;

	case CMD_SCHEDULE_HOST_SVC_DOWNTIME:
            snprintf(help_text,sizeof(help_text),"该命令用于特定主机和它的所有服务的宕机安排.在指定的宕机期间, %s将不会发送关于主机的通知. "
                     "通常, 宕机的主机不会发送在失败状态下关于任何服务警告. 此选项将明确设置该主机所有服务的宕机. "
                     "当宕机安排到期时, 通常情况下%s将会发送通知. 保留宕机安排"
                     "通过计划关闭和重启.",PROGRAM_NAME,PROGRAM_NAME);
            snprintf(action,sizeof(action),"这些主机和主机自身的所有服务的宕机安排");
            break;
            
        case CMD_PROCESS_HOST_CHECK_RESULT:
        case CMD_PROCESS_SERVICE_CHECK_RESULT:
            snprintf(help_text,sizeof(help_text),"该命令用于提交这些%s的被动检查结果. "
                     "一旦要处理它们,对重设%s的相关安全到%s状态特别有用.",(cmd==CMD_PROCESS_HOST_CHECK_RESULT)?"主机" : "服务",(cmd==CMD_PROCESS_HOST_CHECK_RESULT)?"主机" : "服务",(cmd==CMD_PROCESS_HOST_CHECK_RESULT)?"运行":"正常");
			
            snprintf(action,sizeof(action),"提交这些%s的被动检查结果",(cmd==CMD_PROCESS_HOST_CHECK_RESULT)?"主机" : "服务");
            break;
			
        case CMD_ENABLE_HOST_FLAP_DETECTION:
        case CMD_DISABLE_HOST_FLAP_DETECTION:
            snprintf(action,sizeof(action),"%s这些主机的心跳检测",(cmd==CMD_ENABLE_HOST_FLAP_DETECTION)?"启用" : "禁用");
            break;
			
        case CMD_ENABLE_SVC_FLAP_DETECTION:
        case CMD_DISABLE_SVC_FLAP_DETECTION:
            snprintf(action,sizeof(action),"%s这些服务的心跳检测",(cmd==CMD_ENABLE_SVC_FLAP_DETECTION)?"启用" : "禁用");
            break;
			
        case CMD_ENABLE_FLAP_DETECTION:
        case CMD_DISABLE_FLAP_DETECTION:
            snprintf(action,sizeof(action),"在方案基础上%s主机和服务的心跳检测 ",(cmd==CMD_ENABLE_FLAP_DETECTION)?"启用" : "禁用");
            break;
			
        case CMD_ENABLE_HOSTGROUP_SVC_NOTIFICATIONS:
        case CMD_DISABLE_HOSTGROUP_SVC_NOTIFICATIONS:
            snprintf(action,sizeof(action),"%s特定主机组所有服务的通知",(cmd==CMD_ENABLE_HOSTGROUP_SVC_NOTIFICATIONS)?"启用" : "禁用");
            break;
			
        case CMD_ENABLE_HOSTGROUP_HOST_NOTIFICATIONS:
        case CMD_DISABLE_HOSTGROUP_HOST_NOTIFICATIONS:
            snprintf(action,sizeof(action),"%s特定主机组所有主机的通知",(cmd==CMD_ENABLE_HOSTGROUP_HOST_NOTIFICATIONS)?"启用" : "禁用");
            break;
			
        case CMD_ENABLE_HOSTGROUP_SVC_CHECKS:
        case CMD_DISABLE_HOSTGROUP_SVC_CHECKS:
            snprintf(action,sizeof(action),"%s特定主机组所有服务的主动检查",(cmd==CMD_ENABLE_HOSTGROUP_SVC_CHECKS)?"启用" : "禁用");
            break;
			
        case CMD_DEL_HOST_DOWNTIME:
        case CMD_DEL_SVC_DOWNTIME:
            snprintf(action,sizeof(action),"取消这些%s宕机安排",(cmd==CMD_DEL_HOST_DOWNTIME)?"主机" : "服务");
            break;
			
        case CMD_ENABLE_FAILURE_PREDICTION:
        case CMD_DISABLE_FAILURE_PREDICTION:
            snprintf(action,sizeof(action),"在方案基础上%s失败的主机和服务预测",(cmd==CMD_ENABLE_FAILURE_PREDICTION)?"启用" : "禁用");
            break;
			
        case CMD_ENABLE_PERFORMANCE_DATA:
        case CMD_DISABLE_PERFORMANCE_DATA:
            snprintf(action,sizeof(action),"在方案基础上%s主机和服务性能数据处理",(cmd==CMD_ENABLE_PERFORMANCE_DATA)?"启用" : "禁用");
            break;
			
        case CMD_SCHEDULE_HOSTGROUP_HOST_DOWNTIME:
        case CMD_SCHEDULE_HOSTGROUP_SVC_DOWNTIME:
            snprintf(action,sizeof(action),"特定主机组所有%s的宕机安排",(cmd==CMD_SCHEDULE_HOSTGROUP_HOST_DOWNTIME)?"主机" : "服务");
            break;
			
        case CMD_START_ACCEPTING_PASSIVE_HOST_CHECKS:
        case CMD_STOP_ACCEPTING_PASSIVE_HOST_CHECKS:
            snprintf(action,sizeof(action),"在方案基础上%s接收被动检查",(cmd==CMD_START_ACCEPTING_PASSIVE_HOST_CHECKS)?"开始" : "停止");
            break;
            
        case CMD_ENABLE_PASSIVE_HOST_CHECKS:
        case CMD_DISABLE_PASSIVE_HOST_CHECKS:
            snprintf(action,sizeof(action),"%s接收这些主机被动检查",(cmd==CMD_ENABLE_PASSIVE_HOST_CHECKS)?"开始" : "停止");
            break;
			
        case CMD_START_OBSESSING_OVER_HOST_CHECKS:
        case CMD_STOP_OBSESSING_OVER_HOST_CHECKS:
            snprintf(action,sizeof(action),"在方案基础上强迫%s主机被动检查",(cmd==CMD_START_OBSESSING_OVER_HOST_CHECKS)?"开始" : "停止");
            break;
			
        case CMD_START_OBSESSING_OVER_SVC:
        case CMD_STOP_OBSESSING_OVER_SVC:
            snprintf(action,sizeof(action),"强迫%s这些服务",(cmd==CMD_START_OBSESSING_OVER_SVC)?"开始" : "停止");
            break;
			
        case CMD_START_OBSESSING_OVER_HOST:
        case CMD_STOP_OBSESSING_OVER_HOST:
            snprintf(action,sizeof(action),"强迫%s这些主机",(cmd==CMD_START_OBSESSING_OVER_HOST)?"开始" : "停止");
            break;
			
        case CMD_ENABLE_SERVICEGROUP_SVC_NOTIFICATIONS:
        case CMD_DISABLE_SERVICEGROUP_SVC_NOTIFICATIONS:
            snprintf(action,sizeof(action),"%s特定服务组所有服务的通知",(cmd==CMD_ENABLE_SERVICEGROUP_SVC_NOTIFICATIONS)?"启用" : "禁用");
            break;
			
        case CMD_ENABLE_SERVICEGROUP_HOST_NOTIFICATIONS:
        case CMD_DISABLE_SERVICEGROUP_HOST_NOTIFICATIONS:
            snprintf(action,sizeof(action),"%s特定服务组所有主机的通知",(cmd==CMD_ENABLE_SERVICEGROUP_HOST_NOTIFICATIONS)?"启用" : "禁用");
            break;
			
        case CMD_ENABLE_SERVICEGROUP_SVC_CHECKS:
        case CMD_DISABLE_SERVICEGROUP_SVC_CHECKS:
            snprintf(action,sizeof(action),"%s特定服务组所有服务的主动检查 ",(cmd==CMD_ENABLE_SERVICEGROUP_SVC_CHECKS)?"启用" : "禁用");
            break;
			
        case CMD_SCHEDULE_SERVICEGROUP_HOST_DOWNTIME:
            snprintf(action,sizeof(action),"特定服务组所有主机的宕机安排");
            break;
			
        case CMD_SCHEDULE_SERVICEGROUP_SVC_DOWNTIME:
            snprintf(action,sizeof(action),"特定服务组所有服务的宕机安排");
            break;
            
        case CMD_SEND_CUSTOM_HOST_NOTIFICATION:
        case CMD_SEND_CUSTOM_SVC_NOTIFICATION:
            snprintf(help_text,sizeof(help_text),"该命令用于发送关于指定%s的自定义通知. 在紧急情况下使用,您需要通知管理员关于系统监测或服务的问题.",(cmd==CMD_SEND_CUSTOM_HOST_NOTIFICATION)?"主机" : "服务");
            snprintf(action,sizeof(action),"发送自定义%s通知",(cmd==CMD_SEND_CUSTOM_HOST_NOTIFICATION)?"主机" : "服务");
            break;

        case CMD_CHANGE_HOST_MODATTR:
		snprintf(action, sizeof(action), "重置修改的主机属性.");
		break;

        case CMD_CHANGE_SVC_MODATTR:
		snprintf(action, sizeof(action), "重置修改的服务属性.");
		break;

	default:
		print_generic_error_message("亲爱的对不起, 您不能这样做...", "执行一个未知的命令.真为你感到羞愧!", 2);

		return;
	}

	help_text[sizeof(help_text)-1] = '\x0';
	action[sizeof(action)-1] = '\x0';

	/* Javascript to check input */
	printf("<script language=\"JavaScript\">\n");
	printf("function check_input(){\n"
	       "	if (document.getElementById('com_data')) {\n"
	       "		if (document.getElementById('com_data').value == '') {\n"
	       "			document.getElementById('com_data_error').style.display = '';\n"
	       "			return false;\n"
	       "		} else {\n"
	       "			document.getElementById('com_data_error').style.display = 'none';\n"
	       "		}\n"
	       "	}\n"
	       "	if (document.getElementById('plugin_output')) {\n"
	       "		if (document.getElementById('plugin_output').value == '') {\n"
	       "			document.getElementById('plugin_output_error').style.display = '';\n"
	       "			return false;\n"
	       "		} else {\n"
	       "			document.getElementById('plugin_output_error').style.display = 'none';\n"
	       "		}\n"
	       "	}\n"
	       "	if (document.getElementById('not_dly')) {\n"
	       "		if (parseInt(document.getElementById('not_dly').value) == 0 ) {\n"
	       "			document.getElementById('not_dly_error').style.display = '';\n"
	       "			return false;\n"
	       "		}\n"
	       "	}\n"
	       "	return true;\n"
	       "}\n"
	       "</script>\n");

	printf("<div align='center'>\n");

	printf("<form method='post' action='%s' onSubmit=\"return check_input();\">\n", CMD_CGI);

	printf("<INPUT TYPE='HIDDEN' NAME='cmd_typ' VALUE='%d'><INPUT TYPE='HIDDEN' NAME='cmd_mod' VALUE='%d'>\n", cmd, CMDMODE_COMMIT);

	/* creating an extra table to make it compatible to IE6 & IE7 to have a nice frame around the form, damn it */
	printf("<TABLE CELLSPACING='0' CELLPADDING='0'><TR><TD CLASS='boxFrame BoxWidth'>\n");

	printf("<TABLE CELLSPACING='2' CELLPADDING='0' class='contentTable'>\n");

	printf("<tr CLASS='sectionHeader'><td COLSPAN='2'>动作</td></tr>\n");
	printf("<tr><td COLSPAN='2'>%s ", action);
	if (strlen(help_text) > 2)
		print_help_box(help_text);
	printf("</td></tr>\n");

	switch (cmd) {

	case CMD_ADD_SVC_COMMENT:
	case CMD_ACKNOWLEDGE_SVC_PROBLEM:
	case CMD_ADD_HOST_COMMENT:
	case CMD_ACKNOWLEDGE_HOST_PROBLEM:

		if (cmd == CMD_ACKNOWLEDGE_SVC_PROBLEM || cmd == CMD_ADD_SVC_COMMENT)
			print_object_list(PRINT_SERVICE_LIST);
		else
			print_object_list(PRINT_HOST_LIST);

		print_form_element(PRINT_COMMON_HEADER, cmd);
		print_form_element(PRINT_AUTHOR, cmd);
		print_form_element(PRINT_COMMENT_BOX, cmd);
		print_form_element(PRINT_PERSISTENT, cmd);

		if (cmd == CMD_ACKNOWLEDGE_HOST_PROBLEM || cmd == CMD_ACKNOWLEDGE_SVC_PROBLEM) {
			print_form_element(PRINT_EXPIRE_ACKNOWLEDGEMENT, cmd);
			print_form_element(PRINT_STICKY_ACK, cmd);
			print_form_element(PRINT_SEND_NOTFICATION, cmd);
		}

		break;

	case CMD_DEL_HOST_DOWNTIME:
	case CMD_DEL_SVC_DOWNTIME:
	case CMD_DEL_HOST_COMMENT:
	case CMD_DEL_SVC_COMMENT:

		if (cmd == CMD_DEL_HOST_COMMENT || cmd == CMD_DEL_SVC_COMMENT)
			print_object_list(PRINT_COMMENT_LIST);
		else
			print_object_list(PRINT_DOWNTIME_LIST);

		if (enforce_comments_on_actions == TRUE) {
			print_form_element(PRINT_COMMON_HEADER, cmd);
			print_form_element(PRINT_AUTHOR, cmd);
			print_form_element(PRINT_COMMENT_BOX, cmd);
		}

		break;

	case CMD_DEL_DOWNTIME_BY_HOST_NAME:
                print_object_list(PRINT_HOST_LIST);

                print_form_element(PRINT_COMMON_HEADER, cmd);

                if (enforce_comments_on_actions == TRUE) {
                        print_form_element(PRINT_AUTHOR, cmd);
                        print_form_element(PRINT_COMMENT_BOX, cmd);
                }

                break;

	case CMD_DELAY_SVC_NOTIFICATION:
	case CMD_DELAY_HOST_NOTIFICATION:

		if (cmd == CMD_DELAY_SVC_NOTIFICATION)
			print_object_list(PRINT_SERVICE_LIST);
		else
			print_object_list(PRINT_HOST_LIST);

		print_form_element(PRINT_COMMON_HEADER, cmd);

		if (enforce_comments_on_actions == TRUE) {
			print_form_element(PRINT_AUTHOR, cmd);
			print_form_element(PRINT_COMMENT_BOX, cmd);
		}

		print_form_element(PRINT_NOTIFICATION_DELAY, cmd);

		break;

	case CMD_SCHEDULE_SVC_CHECK:
	case CMD_SCHEDULE_HOST_CHECK:
	case CMD_SCHEDULE_HOST_SVC_CHECKS:

		if (cmd == CMD_SCHEDULE_SVC_CHECK)
			print_object_list(PRINT_SERVICE_LIST);
		else
			print_object_list(PRINT_HOST_LIST);

		print_form_element(PRINT_COMMON_HEADER, cmd);

		if (enforce_comments_on_actions == TRUE) {
			print_form_element(PRINT_AUTHOR, cmd);
			print_form_element(PRINT_COMMENT_BOX, cmd);
		}

		print_form_element(PRINT_CHECK_TIME, cmd);
		print_form_element(PRINT_FORCE_CHECK, cmd);

		break;

	case CMD_ENABLE_SVC_CHECK:
	case CMD_DISABLE_SVC_CHECK:
	case CMD_DEL_ALL_SVC_COMMENTS:
	case CMD_ENABLE_SVC_NOTIFICATIONS:
	case CMD_DISABLE_SVC_NOTIFICATIONS:
	case CMD_ENABLE_PASSIVE_SVC_CHECKS:
	case CMD_DISABLE_PASSIVE_SVC_CHECKS:
	case CMD_ENABLE_SVC_EVENT_HANDLER:
	case CMD_DISABLE_SVC_EVENT_HANDLER:
	case CMD_REMOVE_SVC_ACKNOWLEDGEMENT:
	case CMD_ENABLE_SVC_FLAP_DETECTION:
	case CMD_DISABLE_SVC_FLAP_DETECTION:
	case CMD_START_OBSESSING_OVER_SVC:
	case CMD_STOP_OBSESSING_OVER_SVC:

		print_object_list(PRINT_SERVICE_LIST);

		if (enforce_comments_on_actions == TRUE) {
			print_form_element(PRINT_COMMON_HEADER, cmd);
			print_form_element(PRINT_AUTHOR, cmd);
			print_form_element(PRINT_COMMENT_BOX, cmd);
		}

		break;

	case CMD_ENABLE_HOST_SVC_CHECKS:
	case CMD_DISABLE_HOST_SVC_CHECKS:
	case CMD_ENABLE_HOST_SVC_NOTIFICATIONS:
	case CMD_DISABLE_HOST_SVC_NOTIFICATIONS:
	case CMD_ENABLE_HOST_NOTIFICATIONS:
	case CMD_DISABLE_HOST_NOTIFICATIONS:
	case CMD_DEL_ALL_HOST_COMMENTS:
	case CMD_ENABLE_ALL_NOTIFICATIONS_BEYOND_HOST:
	case CMD_DISABLE_ALL_NOTIFICATIONS_BEYOND_HOST:
	case CMD_ENABLE_HOST_EVENT_HANDLER:
	case CMD_DISABLE_HOST_EVENT_HANDLER:
	case CMD_ENABLE_HOST_CHECK:
	case CMD_DISABLE_HOST_CHECK:
	case CMD_REMOVE_HOST_ACKNOWLEDGEMENT:
	case CMD_ENABLE_HOST_FLAP_DETECTION:
	case CMD_DISABLE_HOST_FLAP_DETECTION:
	case CMD_ENABLE_PASSIVE_HOST_CHECKS:
	case CMD_DISABLE_PASSIVE_HOST_CHECKS:
	case CMD_START_OBSESSING_OVER_HOST:
	case CMD_STOP_OBSESSING_OVER_HOST:

		print_object_list(PRINT_HOST_LIST);

		if (enforce_comments_on_actions == TRUE) {
			print_form_element(PRINT_COMMON_HEADER, cmd);
			print_form_element(PRINT_AUTHOR, cmd);
			print_form_element(PRINT_COMMENT_BOX, cmd);
		}

		if (cmd == CMD_ENABLE_HOST_SVC_CHECKS || cmd == CMD_DISABLE_HOST_SVC_CHECKS || cmd == CMD_ENABLE_HOST_SVC_NOTIFICATIONS || cmd == CMD_DISABLE_HOST_SVC_NOTIFICATIONS || cmd == CMD_ENABLE_HOST_NOTIFICATIONS || cmd == CMD_DISABLE_HOST_NOTIFICATIONS) {
			if (enforce_comments_on_actions != TRUE)
				print_form_element(PRINT_COMMON_HEADER, cmd);
		}

		if (cmd == CMD_ENABLE_HOST_SVC_CHECKS || cmd == CMD_DISABLE_HOST_SVC_CHECKS || cmd == CMD_ENABLE_HOST_SVC_NOTIFICATIONS || cmd == CMD_DISABLE_HOST_SVC_NOTIFICATIONS) {

			snprintf(help_text, sizeof(help_text), "同时%s主机的%s.", (cmd == CMD_ENABLE_HOST_SVC_CHECKS || cmd == CMD_ENABLE_HOST_SVC_NOTIFICATIONS) ? "启用" : "禁用", (cmd == CMD_ENABLE_HOST_SVC_CHECKS || cmd == CMD_DISABLE_HOST_SVC_CHECKS) ? "检查" : "通知");
			help_text[sizeof(help_text)-1] = '\x0';

			printf("<tr><td class=\"objectDescription descriptionleft\">同时%s主机:", (cmd == CMD_ENABLE_HOST_SVC_CHECKS || cmd == CMD_ENABLE_HOST_SVC_NOTIFICATIONS) ? "启用" : "禁用");
			print_help_box(help_text);
			printf("</td><td align=\"left\"><INPUT TYPE='checkbox' NAME='ahas'></td></tr>\n");
		}

		if (cmd == CMD_ENABLE_HOST_NOTIFICATIONS || cmd == CMD_DISABLE_HOST_NOTIFICATIONS) {

			snprintf(help_text, sizeof(help_text), "%s发送通知到子主机.", (cmd == CMD_ENABLE_HOST_NOTIFICATIONS) ? "启用" : "禁用");
			help_text[sizeof(help_text)-1] = '\x0';

			printf("<tr><td class=\"objectDescription descriptionleft\"同时%s子主机通知:", (cmd == CMD_ENABLE_HOST_NOTIFICATIONS) ? "启用" : "禁用");
			print_help_box(help_text);
			printf("</td><td align=\"left\"><INPUT TYPE='checkbox' NAME='ptc'></td></tr>\n");
		}
		break;

	case CMD_ENABLE_NOTIFICATIONS:
	case CMD_DISABLE_NOTIFICATIONS:
	case CMD_SHUTDOWN_PROCESS:
	case CMD_RESTART_PROCESS:
	case CMD_START_EXECUTING_SVC_CHECKS:
	case CMD_STOP_EXECUTING_SVC_CHECKS:
	case CMD_START_ACCEPTING_PASSIVE_SVC_CHECKS:
	case CMD_STOP_ACCEPTING_PASSIVE_SVC_CHECKS:
	case CMD_ENABLE_EVENT_HANDLERS:
	case CMD_DISABLE_EVENT_HANDLERS:
	case CMD_START_OBSESSING_OVER_SVC_CHECKS:
	case CMD_STOP_OBSESSING_OVER_SVC_CHECKS:
	case CMD_ENABLE_FLAP_DETECTION:
	case CMD_DISABLE_FLAP_DETECTION:
	case CMD_ENABLE_FAILURE_PREDICTION:
	case CMD_DISABLE_FAILURE_PREDICTION:
	case CMD_ENABLE_PERFORMANCE_DATA:
	case CMD_DISABLE_PERFORMANCE_DATA:
	case CMD_START_EXECUTING_HOST_CHECKS:
	case CMD_STOP_EXECUTING_HOST_CHECKS:
	case CMD_START_ACCEPTING_PASSIVE_HOST_CHECKS:
	case CMD_STOP_ACCEPTING_PASSIVE_HOST_CHECKS:
	case CMD_START_OBSESSING_OVER_HOST_CHECKS:
	case CMD_STOP_OBSESSING_OVER_HOST_CHECKS:

		if (cmd == CMD_DISABLE_NOTIFICATIONS) {
			print_form_element(PRINT_EXPIRE_DISABLE_NOTIFICATIONS, cmd);
		}
		if (enforce_comments_on_actions == TRUE) {
			print_form_element(PRINT_COMMON_HEADER, cmd);
			print_form_element(PRINT_AUTHOR, cmd);
			print_form_element(PRINT_COMMENT_BOX, cmd);
		} else	{
			if (cmd != CMD_DISABLE_NOTIFICATIONS) {
				printf("<tr><td COLSPAN=\"2\">&nbsp;</td></tr>\n");
				printf("<tr><td CLASS='objectDescription' colspan=2>此命令无选项.<br>点击'注释'按钮提交该命令.</td></tr>\n");
			}
		}

		break;

	case CMD_PROCESS_HOST_CHECK_RESULT:
	case CMD_PROCESS_SERVICE_CHECK_RESULT:

		if (cmd == CMD_PROCESS_SERVICE_CHECK_RESULT)
			print_object_list(PRINT_SERVICE_LIST);
		else
			print_object_list(PRINT_HOST_LIST);

		print_form_element(PRINT_COMMON_HEADER, cmd);

		if (enforce_comments_on_actions == TRUE) {
			print_form_element(PRINT_AUTHOR, cmd);
			print_form_element(PRINT_COMMENT_BOX, cmd);
		}

		snprintf(help_text, sizeof(help_text), "设置该%s发送到%s的状态.", PROGRAM_NAME, (cmd == CMD_PROCESS_HOST_CHECK_RESULT) ? "主机" : "服务");
		help_text[sizeof(help_text)-1] = '\x0';

		printf("<tr><td class=\"objectDescription descriptionleft\">检查结果:");
		print_help_box(help_text);
		printf("</td><td align=\"left\">\n");
		printf("\t<SELECT NAME='plugin_state'>\n");
		if (cmd == CMD_PROCESS_SERVICE_CHECK_RESULT) {
             printf("\t\t<OPTION VALUE=%d SELECTED>正常</OPTION>\n",STATE_OK);
			 printf("\t\t<OPTION VALUE=%d>警报</OPTION>\n",STATE_WARNING);
			 printf("\t\t<OPTION VALUE=%d>未知</OPTION>\n",STATE_UNKNOWN);
			 printf("\t\t<OPTION VALUE=%d>严重</OPTION>\n",STATE_CRITICAL);
		}else{
			 printf("\t\t<OPTION VALUE=0 SELECTED>运行</OPTION>\n");
			 printf("\t\t<OPTION VALUE=1>宕机</OPTION>\n");
			 printf("\t\t<OPTION VALUE=2>不可达</OPTION>\n");
		}
		printf("\t</SELECT>\n");
		printf("</td></tr>\n");

		print_form_element(PRINT_CHECK_OUTPUT_BOX, cmd);
		print_form_element(PRINT_PERFORMANCE_DATA_BOX, cmd);

		break;

	case CMD_SCHEDULE_HOST_DOWNTIME:
	case CMD_SCHEDULE_HOST_SVC_DOWNTIME:
	case CMD_SCHEDULE_SVC_DOWNTIME:

		if (cmd == CMD_SCHEDULE_SVC_DOWNTIME)
			print_object_list(PRINT_SERVICE_LIST);
		else
			print_object_list(PRINT_HOST_LIST);

		print_form_element(PRINT_COMMON_HEADER, cmd);
		print_form_element(PRINT_AUTHOR, cmd);
		print_form_element(PRINT_COMMENT_BOX, cmd);

		snprintf(help_text, sizeof(help_text), "如果宕机由另一个特定%s的宕机获取触发,这里定义.", (cmd == CMD_PROCESS_HOST_CHECK_RESULT) ? "主机" : "服务");
		help_text[sizeof(help_text)-1] = '\x0';

		printf("<tr id=\"trigger_select\"><td class=\"objectDescription descriptionleft\">目标:");
		print_help_box(help_text);
		printf("</td><td align=\"left\">\n");
		printf("\t<SELECT name='trigger'>\n");
		printf("\t\t<OPTION VALUE='0'>无</OPTION>\n");

		for (temp_downtime = scheduled_downtime_list; temp_downtime != NULL; temp_downtime = temp_downtime->next) {
			if (temp_downtime->type != HOST_DOWNTIME)
				continue;

			/* find the host... */
			temp_host = find_host(temp_downtime->host_name);

			/* make sure user has rights to view this host */
			if (is_authorized_for_host(temp_host, &current_authdata) == FALSE)
				continue;

			printf("\t\t<OPTION VALUE='%lu'>", temp_downtime->downtime_id);
			get_time_string(&temp_downtime->start_time, start_time, sizeof(start_time), SHORT_DATE_TIME);
			printf("ID: %lu, 主机'%s'开始 @ %s</OPTION>\n", temp_downtime->downtime_id, temp_downtime->host_name, start_time);
			found_trigger_objects = TRUE;
		}
		for (temp_downtime = scheduled_downtime_list; temp_downtime != NULL; temp_downtime = temp_downtime->next) {
			if (temp_downtime->type != SERVICE_DOWNTIME)
				continue;

			printf("\t\t<OPTION VALUE='%lu'>", temp_downtime->downtime_id);
			get_time_string(&temp_downtime->start_time, start_time, sizeof(start_time), SHORT_DATE_TIME);
			printf("ID: %lu, 主机'%s'的服'%s'开始 @ %s</OPTION>\n", temp_downtime->downtime_id, temp_downtime->host_name, temp_downtime->service_description, start_time);
			found_trigger_objects = TRUE;
		}

		printf("\t</SELECT>\n");
		printf("</td></tr>\n");

		/* hide "Triggerd by" selction if nothing is found to get triggerd from */
		if (!found_trigger_objects)
			printf("<tr style=\"display:none;\"><td colspan=2><script language=\"JavaScript\">document.getElementById('trigger_select').style.display = 'none';</script></td></tr>\n");

		print_form_element(PRINT_START_TIME, cmd);
		print_form_element(PRINT_END_TIME, cmd);
		print_form_element(PRINT_FIXED_FLEXIBLE_TYPE, cmd);

		if (cmd == CMD_SCHEDULE_HOST_DOWNTIME) {
			snprintf(help_text, sizeof(help_text), "这里定义这些主机的子主机应该怎么做.");
			help_text[sizeof(help_text)-1] = '\x0';

			printf("<tr><td class=\"objectDescription descriptionleft\">子主机:");
			print_help_box(help_text);
			printf("</td><td align=\"left\">\n");
			printf("\t<SELECT name='childoptions'>\n");
			printf("\t\t<OPTION VALUE='0'>子主机不受任何影响</OPTION>\n");
			printf("\t\t<OPTION VALUE='1'>所有子主机安排触发宕机</OPTION>\n");
			printf("\t\t<OPTION VALUE='2'>所有子主机安非排触发宕机</OPTION>\n");
			printf("\t</SELECT>\n");
			printf("</td></tr>\n");
		}

		break;

	case CMD_ENABLE_HOSTGROUP_SVC_NOTIFICATIONS:
	case CMD_DISABLE_HOSTGROUP_SVC_NOTIFICATIONS:
	case CMD_ENABLE_HOSTGROUP_HOST_NOTIFICATIONS:
	case CMD_DISABLE_HOSTGROUP_HOST_NOTIFICATIONS:
	case CMD_ENABLE_HOSTGROUP_SVC_CHECKS:
	case CMD_DISABLE_HOSTGROUP_SVC_CHECKS:

		printf("<tr><td COLSPAN=\"2\">&nbsp;</td></tr>\n");
		printf("<tr class=\"statusEven\" ><td width=\"50%%\" style=\"font-weight:bold;\">主机组名称:</td>");
		printf("<td><INPUT TYPE='HIDDEN' NAME='hostgroup' VALUE='%s'>%s</td></tr>\n", escape_string(hostgroup_name), escape_string(hostgroup_name));

		if (enforce_comments_on_actions == TRUE) {
			print_form_element(PRINT_COMMON_HEADER, cmd);
			print_form_element(PRINT_AUTHOR, cmd);
			print_form_element(PRINT_COMMENT_BOX, cmd);
		}

		if (cmd == CMD_ENABLE_HOSTGROUP_SVC_CHECKS || cmd == CMD_DISABLE_HOSTGROUP_SVC_CHECKS || cmd == CMD_ENABLE_HOSTGROUP_SVC_NOTIFICATIONS || cmd == CMD_DISABLE_HOSTGROUP_SVC_NOTIFICATIONS) {

			if (enforce_comments_on_actions != TRUE)
				print_form_element(PRINT_COMMON_HEADER, cmd);

			printf("<tr><td class=\"objectDescription descriptionleft\">同时%s主机:</td><td align=\"left\">\n", (cmd == CMD_ENABLE_HOSTGROUP_SVC_CHECKS || cmd == CMD_ENABLE_HOSTGROUP_SVC_NOTIFICATIONS) ? "启用" : "禁用");
			printf("<INPUT TYPE='checkbox' NAME='ahas'></td></tr>\n");
		}
		break;

	case CMD_ENABLE_SERVICEGROUP_SVC_NOTIFICATIONS:
	case CMD_DISABLE_SERVICEGROUP_SVC_NOTIFICATIONS:
	case CMD_ENABLE_SERVICEGROUP_HOST_NOTIFICATIONS:
	case CMD_DISABLE_SERVICEGROUP_HOST_NOTIFICATIONS:
	case CMD_ENABLE_SERVICEGROUP_SVC_CHECKS:
	case CMD_DISABLE_SERVICEGROUP_SVC_CHECKS:

		printf("<tr><td COLSPAN=\"2\">&nbsp;</td></tr>\n");
		printf("<tr class=\"statusEven\"><td width=\"50%%\" style=\"font-weight:bold;\">服务组名称:</td>");
		printf("<td><INPUT TYPE='HIDDEN' NAME='servicegroup' VALUE='%s'>%s</td></tr>\n", escape_string(servicegroup_name), escape_string(servicegroup_name));

		if (enforce_comments_on_actions == TRUE) {
			print_form_element(PRINT_COMMON_HEADER, cmd);
			print_form_element(PRINT_AUTHOR, cmd);
			print_form_element(PRINT_COMMENT_BOX, cmd);
		}

		if (cmd == CMD_ENABLE_SERVICEGROUP_SVC_CHECKS || cmd == CMD_DISABLE_SERVICEGROUP_SVC_CHECKS || cmd == CMD_ENABLE_SERVICEGROUP_SVC_NOTIFICATIONS || cmd == CMD_DISABLE_SERVICEGROUP_SVC_NOTIFICATIONS) {

			if (enforce_comments_on_actions != TRUE)
				print_form_element(PRINT_COMMON_HEADER, cmd);

			printf("<tr><td class=\"objectDescription descriptionleft\">同时%s主机:</td><td align=\"left\">\n", (cmd == CMD_ENABLE_SERVICEGROUP_SVC_CHECKS || cmd == CMD_ENABLE_SERVICEGROUP_SVC_NOTIFICATIONS) ? "启用" : "禁用");
			printf("<INPUT TYPE='checkbox' NAME='ahas'></td></tr>\n");
		}
		break;

	case CMD_SCHEDULE_HOSTGROUP_HOST_DOWNTIME:
	case CMD_SCHEDULE_HOSTGROUP_SVC_DOWNTIME:
	case CMD_SCHEDULE_SERVICEGROUP_HOST_DOWNTIME:
	case CMD_SCHEDULE_SERVICEGROUP_SVC_DOWNTIME:

		printf("<tr><td COLSPAN=\"2\">&nbsp;</td></tr>\n");
		printf("<tr class=\"statusEven\"><td width=\"50%%\" style=\"font-weight:bold;\">");
		if (cmd == CMD_SCHEDULE_HOSTGROUP_HOST_DOWNTIME || cmd == CMD_SCHEDULE_HOSTGROUP_SVC_DOWNTIME)
			printf("主机组名称:</td><td><INPUT TYPE='HIDDEN' NAME='hostgroup' VALUE='%s'>%s</td></tr>\n", escape_string(hostgroup_name), escape_string(hostgroup_name));
		else
			printf("服务组名称:</td><td><INPUT TYPE='HIDDEN' NAME='servicegroup' VALUE='%s'>%s</td></tr>\n", escape_string(servicegroup_name), escape_string(servicegroup_name));

		print_form_element(PRINT_COMMON_HEADER, cmd);
		print_form_element(PRINT_AUTHOR, cmd);
		print_form_element(PRINT_COMMENT_BOX, cmd);
		print_form_element(PRINT_START_TIME, cmd);
		print_form_element(PRINT_END_TIME, cmd);
		print_form_element(PRINT_FIXED_FLEXIBLE_TYPE, cmd);

		if (cmd == CMD_SCHEDULE_HOSTGROUP_SVC_DOWNTIME || cmd == CMD_SCHEDULE_SERVICEGROUP_SVC_DOWNTIME) {
			printf("<tr><td class=\"objectDescription descriptionleft\">>同时对主机安排宕机:</td><td align=\"left\">\n");
			printf("<INPUT TYPE='checkbox' NAME='ahas'></td></tr>\n");
		}
		break;

	case CMD_SEND_CUSTOM_HOST_NOTIFICATION:
	case CMD_SEND_CUSTOM_SVC_NOTIFICATION:

		if (cmd == CMD_SEND_CUSTOM_SVC_NOTIFICATION)
			print_object_list(PRINT_SERVICE_LIST);
		else
			print_object_list(PRINT_HOST_LIST);

		print_form_element(PRINT_COMMON_HEADER, cmd);
		print_form_element(PRINT_AUTHOR, cmd);
		print_form_element(PRINT_COMMENT_BOX, cmd);
		print_form_element(PRINT_FORCE_NOTIFICATION, cmd);
		print_form_element(PRINT_BROADCAST_NOTIFICATION, cmd);

		break;

        case CMD_CHANGE_HOST_MODATTR:
		print_object_list(PRINT_HOST_LIST);
		print_form_element(PRINT_COMMON_HEADER, cmd);
		printf("<tr class=\"statusEven\"><td width=\"50%%\" style=\"font-weight:bold;\">属性修改:</td>");
		printf("<td><INPUT TYPE='HIDDEN' NAME='attr' VALUE='%lu'>", attr);
		print_modified_attributes(HTML_CONTENT, CMD_CGI, attr);
		printf("</td></tr>\n");
		break;

        case CMD_CHANGE_SVC_MODATTR:
		print_object_list(PRINT_SERVICE_LIST);
		print_form_element(PRINT_COMMON_HEADER, cmd);
		printf("<tr class=\"statusEven\"><td width=\"50%%\" style=\"font-weight:bold;\">属性修改:</td>");
		printf("<td><INPUT TYPE='HIDDEN' NAME='attr' VALUE='%lu'>", attr);
		print_modified_attributes(HTML_CONTENT, CMD_CGI, attr);
		printf("</td></tr>\n");
		break;

	default:
		printf("<tr><td CLASS='objectDescription' COLSPAN=\"2\">这个本不该发生... :-(</td></tr>\n");
	}


	printf("<tr><td COLSPAN=\"2\">&nbsp;</td></tr>\n");
	printf("<tr CLASS='sectionHeader'><td COLSPAN=\"2\" class=\"commitButton\"><INPUT TYPE=\"submit\" NAME=\"btnSubmit\" VALUE=\"提交\" class=\"submitButton\">&nbsp;&nbsp;|&nbsp;&nbsp;<a HREF=\"javascript:window.history.go(-1)\">取消</a></td></tr>\n");

	printf("</table>\n");
	printf("</td></tr></table>\n"); /* Outer frame */
	printf("</form>\n");

	printf("</div>\n");

	return;
}

void commit_command_data(int cmd) {
	char error_string[MAX_INPUT_BUFFER];
	service *temp_service;
	host *temp_host;
	hostgroup *temp_hostgroup;
	comment *temp_comment;
	scheduled_downtime *temp_downtime;
	servicegroup *temp_servicegroup = NULL;
	contact *temp_contact = NULL;
	int x = 0;
	int e = 0;
	short error_found = FALSE;
	short cmd_has_objects = FALSE;
	short row_color = 0;

	/* get authentication information */
	get_authentication_information(&current_authdata);

	/* allways set the first element to FALSE*/
	/* If there is a single COMMAND witch is not coverd correctly throught the following cases it won't get executed */
	is_authorized[x] = FALSE;

	/* get name to use for author */
	if (lock_author_names == TRUE) {
		temp_contact = find_contact(current_authdata.username);
		if (temp_contact != NULL && temp_contact->alias != NULL)
			comment_author = temp_contact->alias;
		else
			comment_author = current_authdata.username;
	}

	switch (cmd) {


	case CMD_ADD_HOST_COMMENT:
	case CMD_ADD_SVC_COMMENT:
	case CMD_ACKNOWLEDGE_HOST_PROBLEM:
	case CMD_ACKNOWLEDGE_SVC_PROBLEM:
	case CMD_SEND_CUSTOM_HOST_NOTIFICATION:
	case CMD_SEND_CUSTOM_SVC_NOTIFICATION:

		/* make sure we have author name, and comment data... */
		check_comment_sanity(&e);

		/* clean up the comment data */
		clean_comment_data(comment_author);
		clean_comment_data(comment_data);

		if (use_ack_end_time == TRUE && (cmd == CMD_ACKNOWLEDGE_HOST_PROBLEM || cmd == CMD_ACKNOWLEDGE_SVC_PROBLEM)) {

			time(&start_time);

			/* make sure we have end time if required */
			check_time_sanity(&e);
		} else
			end_time = 0L;

		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {

			cmd_has_objects = TRUE;

			if (commands[x].host_name == NULL)
				continue;

			/* see if the user is authorized to issue a command... */
			is_authorized[x] = FALSE;
			if (cmd == CMD_ADD_HOST_COMMENT || cmd == CMD_ACKNOWLEDGE_HOST_PROBLEM || cmd == CMD_SEND_CUSTOM_HOST_NOTIFICATION) {
				temp_host = find_host(commands[x].host_name);
				if (is_authorized_for_host_commands(temp_host, &current_authdata) == TRUE)
					is_authorized[x] = TRUE;
			} else {
				temp_service = find_service(commands[x].host_name, commands[x].description);
				if (is_authorized_for_service_commands(temp_service, &current_authdata) == TRUE)
					is_authorized[x] = TRUE;
			}
		}
		break;

	case CMD_DEL_HOST_COMMENT:
	case CMD_DEL_SVC_COMMENT:

		if (enforce_comments_on_actions == TRUE) {
			check_comment_sanity(&e);
			clean_comment_data(comment_author);
			clean_comment_data(comment_data);
		}

		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {

			cmd_has_objects = TRUE;

			if (multi_ids[x] == FALSE)
				continue;

			/* check the sanity of the comment id */
			if (multi_ids[x] == 0) {
				error[e++].message = strdup("注解id不能为0");
				continue;
			}

			/* find the comment */
			if (cmd == CMD_DEL_HOST_COMMENT)
				temp_comment = find_host_comment(multi_ids[x]);
			else
				temp_comment = find_service_comment(multi_ids[x]);

			/* see if the user is authorized to issue a command... */
			is_authorized[x] = FALSE;
			if (cmd == CMD_DEL_HOST_COMMENT && temp_comment != NULL) {
				temp_host = find_host(temp_comment->host_name);
				if (is_authorized_for_host_commands(temp_host, &current_authdata) == TRUE)
					is_authorized[x] = TRUE;
			}
			if (cmd == CMD_DEL_SVC_COMMENT && temp_comment != NULL) {
				temp_service = find_service(temp_comment->host_name, temp_comment->service_description);
				if (is_authorized_for_service_commands(temp_service, &current_authdata) == TRUE)
					is_authorized[x] = TRUE;
			}
		}

		/* free comment data */
		free_comment_data();

		break;

	case CMD_DEL_HOST_DOWNTIME:
	case CMD_DEL_SVC_DOWNTIME:

		if (enforce_comments_on_actions == TRUE) {
			check_comment_sanity(&e);
			clean_comment_data(comment_author);
			clean_comment_data(comment_data);
		}

		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {

			cmd_has_objects = TRUE;

			if (multi_ids[x] == FALSE)
				continue;

			/* check the sanity of the downtime id */
			if (multi_ids[x] == 0) {
				error[e++].message = strdup("宕机id不能为0");
				continue;
			}

			/* find the downtime entry */
			if (cmd == CMD_DEL_HOST_DOWNTIME)
				temp_downtime = find_host_downtime(multi_ids[x]);
			else
				temp_downtime = find_service_downtime(multi_ids[x]);

			/* see if the user is authorized to issue a command... */
			is_authorized[x] = FALSE;
			if (cmd == CMD_DEL_HOST_DOWNTIME && temp_downtime != NULL) {
				temp_host = find_host(temp_downtime->host_name);
				if (is_authorized_for_host_commands(temp_host, &current_authdata) == TRUE)
					is_authorized[x] = TRUE;
			}
			if (cmd == CMD_DEL_SVC_DOWNTIME && temp_downtime != NULL) {
				temp_service = find_service(temp_downtime->host_name, temp_downtime->service_description);
				if (is_authorized_for_service_commands(temp_service, &current_authdata) == TRUE)
					is_authorized[x] = TRUE;
			}
		}

		/* free downtime data */
		free_downtime_data();

		break;

	case CMD_SCHEDULE_SVC_CHECK:
	case CMD_ENABLE_SVC_CHECK:
	case CMD_DISABLE_SVC_CHECK:
	case CMD_DEL_ALL_SVC_COMMENTS:
	case CMD_ENABLE_SVC_NOTIFICATIONS:
	case CMD_DISABLE_SVC_NOTIFICATIONS:
	case CMD_ENABLE_PASSIVE_SVC_CHECKS:
	case CMD_DISABLE_PASSIVE_SVC_CHECKS:
	case CMD_ENABLE_SVC_EVENT_HANDLER:
	case CMD_DISABLE_SVC_EVENT_HANDLER:
	case CMD_REMOVE_SVC_ACKNOWLEDGEMENT:
	case CMD_PROCESS_SERVICE_CHECK_RESULT:
	case CMD_SCHEDULE_SVC_DOWNTIME:
	case CMD_DELAY_SVC_NOTIFICATION:
	case CMD_ENABLE_SVC_FLAP_DETECTION:
	case CMD_DISABLE_SVC_FLAP_DETECTION:
	case CMD_START_OBSESSING_OVER_SVC:
	case CMD_STOP_OBSESSING_OVER_SVC:

		if (cmd == CMD_SCHEDULE_SVC_DOWNTIME || enforce_comments_on_actions == TRUE) {
			/* make sure we have author and comment data */
			check_comment_sanity(&e);

			/* make sure we have start/end times for downtime */
			if (cmd == CMD_SCHEDULE_SVC_DOWNTIME)
				check_time_sanity(&e);

			/* clean up the comment data if scheduling downtime */
			clean_comment_data(comment_author);
			clean_comment_data(comment_data);
		}

		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {

			cmd_has_objects = TRUE;

			if (commands[x].host_name == NULL || commands[x].description == NULL)
				continue;

			is_authorized[x] = FALSE;
			temp_service = find_service(commands[x].host_name, commands[x].description);
			if (is_authorized_for_service_commands(temp_service, &current_authdata) == TRUE)
				is_authorized[x] = TRUE;
		}

		/* make sure we have passive check info (if necessary) */
		if (cmd == CMD_PROCESS_SERVICE_CHECK_RESULT && !strcmp(plugin_output, ""))
			error[e++].message = strdup("检查输出不能空");

		/* make sure we have a notification delay (if necessary) */
		if (cmd == CMD_DELAY_SVC_NOTIFICATION && notification_delay <= 0)
			error[e++].message = strdup("通知延迟必须大于0");

		/* make sure we have check time (if necessary) */
		if (cmd == CMD_SCHEDULE_SVC_CHECK && start_time == (time_t)0)
			error[e++].message = strdup("开始时间必须是非零或提交的格式错误");

		break;

	case CMD_ENABLE_NOTIFICATIONS:
	case CMD_DISABLE_NOTIFICATIONS:
	case CMD_SHUTDOWN_PROCESS:
	case CMD_RESTART_PROCESS:
	case CMD_START_EXECUTING_SVC_CHECKS:
	case CMD_STOP_EXECUTING_SVC_CHECKS:
	case CMD_START_ACCEPTING_PASSIVE_SVC_CHECKS:
	case CMD_STOP_ACCEPTING_PASSIVE_SVC_CHECKS:
	case CMD_ENABLE_EVENT_HANDLERS:
	case CMD_DISABLE_EVENT_HANDLERS:
	case CMD_START_OBSESSING_OVER_SVC_CHECKS:
	case CMD_STOP_OBSESSING_OVER_SVC_CHECKS:
	case CMD_ENABLE_FLAP_DETECTION:
	case CMD_DISABLE_FLAP_DETECTION:
	case CMD_ENABLE_FAILURE_PREDICTION:
	case CMD_DISABLE_FAILURE_PREDICTION:
	case CMD_ENABLE_PERFORMANCE_DATA:
	case CMD_DISABLE_PERFORMANCE_DATA:
	case CMD_START_EXECUTING_HOST_CHECKS:
	case CMD_STOP_EXECUTING_HOST_CHECKS:
	case CMD_START_ACCEPTING_PASSIVE_HOST_CHECKS:
	case CMD_STOP_ACCEPTING_PASSIVE_HOST_CHECKS:
	case CMD_START_OBSESSING_OVER_HOST_CHECKS:
	case CMD_STOP_OBSESSING_OVER_HOST_CHECKS:

                if (use_disabled_notif_end_time == TRUE && cmd == CMD_DISABLE_NOTIFICATIONS) {

                        time(&start_time);

                        /* make sure we have end time if required */
                        check_time_sanity(&e);
                } else
                        end_time = 0L;

		if (enforce_comments_on_actions == TRUE) {
			check_comment_sanity(&e);
			clean_comment_data(comment_author);
			clean_comment_data(comment_data);
		}

		/* see if the user is authorized to issue a command... */
		is_authorized[x] = FALSE;
		if (is_authorized_for_system_commands(&current_authdata) == TRUE)
			is_authorized[x] = TRUE;
		break;

	case CMD_ENABLE_HOST_SVC_CHECKS:
	case CMD_DISABLE_HOST_SVC_CHECKS:
	case CMD_DEL_ALL_HOST_COMMENTS:
	case CMD_SCHEDULE_HOST_SVC_CHECKS:
	case CMD_ENABLE_HOST_NOTIFICATIONS:
	case CMD_DISABLE_HOST_NOTIFICATIONS:
	case CMD_ENABLE_ALL_NOTIFICATIONS_BEYOND_HOST:
	case CMD_DISABLE_ALL_NOTIFICATIONS_BEYOND_HOST:
	case CMD_ENABLE_HOST_SVC_NOTIFICATIONS:
	case CMD_DISABLE_HOST_SVC_NOTIFICATIONS:
	case CMD_ENABLE_HOST_EVENT_HANDLER:
	case CMD_DISABLE_HOST_EVENT_HANDLER:
	case CMD_ENABLE_HOST_CHECK:
	case CMD_DISABLE_HOST_CHECK:
	case CMD_REMOVE_HOST_ACKNOWLEDGEMENT:
	case CMD_SCHEDULE_HOST_DOWNTIME:
	case CMD_SCHEDULE_HOST_SVC_DOWNTIME:
	case CMD_DELAY_HOST_NOTIFICATION:
	case CMD_ENABLE_HOST_FLAP_DETECTION:
	case CMD_DISABLE_HOST_FLAP_DETECTION:
	case CMD_PROCESS_HOST_CHECK_RESULT:
	case CMD_ENABLE_PASSIVE_HOST_CHECKS:
	case CMD_DISABLE_PASSIVE_HOST_CHECKS:
	case CMD_SCHEDULE_HOST_CHECK:
	case CMD_START_OBSESSING_OVER_HOST:
	case CMD_STOP_OBSESSING_OVER_HOST:
	case CMD_DEL_DOWNTIME_BY_HOST_NAME:

		if (cmd == CMD_SCHEDULE_HOST_DOWNTIME || cmd == CMD_SCHEDULE_HOST_SVC_DOWNTIME || enforce_comments_on_actions == TRUE) {
			/* make sure we have author and comment data */
			check_comment_sanity(&e);

			/* make sure we have start/end times for downtime */
			if (cmd == CMD_SCHEDULE_HOST_DOWNTIME || cmd == CMD_SCHEDULE_HOST_SVC_DOWNTIME)
				check_time_sanity(&e);

			/* clean up the comment data if scheduling downtime */
			clean_comment_data(comment_author);
			clean_comment_data(comment_data);
		}

		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {

			cmd_has_objects = TRUE;

			if (commands[x].host_name == NULL)
				continue;

			/* see if the user is authorized to issue a command... */
			is_authorized[x] = FALSE;
			temp_host = find_host(commands[x].host_name);
			if (is_authorized_for_host_commands(temp_host, &current_authdata) == TRUE)
				is_authorized[x] = TRUE;
		}

		/* make sure we have a notification delay (if necessary) */
		if (cmd == CMD_DELAY_HOST_NOTIFICATION && notification_delay <= 0)
			error[e++].message = strdup("通知延迟必须大于0");

		/* make sure we have check time (if necessary) */
		if ((cmd == CMD_SCHEDULE_HOST_CHECK || cmd == CMD_SCHEDULE_HOST_SVC_CHECKS) && start_time == (time_t)0)
			error[e++].message = strdup("开始时间必须是非零或提交的格式错误");

		/* make sure we have passive check info (if necessary) */
		if (cmd == CMD_PROCESS_HOST_CHECK_RESULT && !strcmp(plugin_output, ""))
			error[e++].message = strdup("检查输出不能为空");

		break;

	case CMD_ENABLE_HOSTGROUP_SVC_NOTIFICATIONS:
	case CMD_DISABLE_HOSTGROUP_SVC_NOTIFICATIONS:
	case CMD_ENABLE_HOSTGROUP_HOST_NOTIFICATIONS:
	case CMD_DISABLE_HOSTGROUP_HOST_NOTIFICATIONS:
	case CMD_ENABLE_HOSTGROUP_SVC_CHECKS:
	case CMD_DISABLE_HOSTGROUP_SVC_CHECKS:
	case CMD_SCHEDULE_HOSTGROUP_HOST_DOWNTIME:
	case CMD_SCHEDULE_HOSTGROUP_SVC_DOWNTIME:
	case CMD_ENABLE_SERVICEGROUP_SVC_NOTIFICATIONS:
	case CMD_DISABLE_SERVICEGROUP_SVC_NOTIFICATIONS:
	case CMD_ENABLE_SERVICEGROUP_HOST_NOTIFICATIONS:
	case CMD_DISABLE_SERVICEGROUP_HOST_NOTIFICATIONS:
	case CMD_ENABLE_SERVICEGROUP_SVC_CHECKS:
	case CMD_DISABLE_SERVICEGROUP_SVC_CHECKS:
	case CMD_SCHEDULE_SERVICEGROUP_HOST_DOWNTIME:
	case CMD_SCHEDULE_SERVICEGROUP_SVC_DOWNTIME:


		if (cmd == CMD_SCHEDULE_SERVICEGROUP_HOST_DOWNTIME || cmd == CMD_SCHEDULE_SERVICEGROUP_SVC_DOWNTIME \
		        || cmd == CMD_SCHEDULE_HOSTGROUP_HOST_DOWNTIME || cmd == CMD_SCHEDULE_HOSTGROUP_SVC_DOWNTIME) {
			/* make sure we have author and comment data */
			check_comment_sanity(&e);

			/* make sure we have start/end times for downtime */
			check_time_sanity(&e);

			/* clean up the comment data if scheduling downtime */
			clean_comment_data(comment_author);
			clean_comment_data(comment_data);
		} else if (enforce_comments_on_actions == TRUE) {
			check_comment_sanity(&e);
			clean_comment_data(comment_author);
			clean_comment_data(comment_data);
		}

		/* see if the user is authorized to issue a command... */
		is_authorized[x] = FALSE;
		if (cmd == CMD_ENABLE_HOSTGROUP_SVC_NOTIFICATIONS	|| cmd == CMD_DISABLE_HOSTGROUP_SVC_NOTIFICATIONS || \
		        cmd == CMD_ENABLE_HOSTGROUP_HOST_NOTIFICATIONS || cmd == CMD_DISABLE_HOSTGROUP_HOST_NOTIFICATIONS || \
		        cmd == CMD_ENABLE_HOSTGROUP_SVC_CHECKS		|| cmd == CMD_DISABLE_HOSTGROUP_SVC_CHECKS || \
		        cmd == CMD_SCHEDULE_HOSTGROUP_HOST_DOWNTIME	|| cmd == CMD_SCHEDULE_HOSTGROUP_SVC_DOWNTIME) {
			temp_hostgroup = find_hostgroup(hostgroup_name);
			if (is_authorized_for_hostgroup_commands(temp_hostgroup, &current_authdata) == TRUE)
				is_authorized[x] = TRUE;
		} else {
			temp_servicegroup = find_servicegroup(servicegroup_name);
			if (is_authorized_for_servicegroup_commands(temp_servicegroup, &current_authdata) == TRUE)
				is_authorized[x] = TRUE;
		}

		break;

	case CMD_CHANGE_HOST_MODATTR:
	case CMD_CHANGE_SVC_MODATTR:

                for (x = 0; x < NUMBER_OF_STRUCTS; x++) {

                        cmd_has_objects = TRUE;

                        if (commands[x].host_name == NULL)
                                continue;

                        /* see if the user is authorized to issue a command... */
                        is_authorized[x] = FALSE;
                        if (cmd == CMD_CHANGE_HOST_MODATTR) {
                                temp_host = find_host(commands[x].host_name);
                                if (is_authorized_for_host_commands(temp_host, &current_authdata) == TRUE)
                                        is_authorized[x] = TRUE;
                        } else {
                                temp_service = find_service(commands[x].host_name, commands[x].description);
                                if (is_authorized_for_service_commands(temp_service, &current_authdata) == TRUE)
                                        is_authorized[x] = TRUE;
                        }

			/* do not allow other attributes than reset (0) */
			if (attr != MODATTR_NONE) {
				error[e++].message = strdup("You cannot change modified attributes other than reset them!");
			}
                }

		break;

	default:
		print_generic_error_message("亲爱的对不起,您不能这样做...","执行了一个未知命令?真为你感到难过!", 2);

		return;
	}


	/*
	 * these are supposed to be implanted inside the
	 * completed commands shipped off to Icinga and
	 * must therefore never contain ';'
	 */
	for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
		if (commands[x].host_name == NULL)
			continue;

		if (strchr(commands[x].host_name, ';')) {
			snprintf(error_string, sizeof(error_string), "主机名\"%s\"包含分号", commands[x].host_name);
			error_string[sizeof(error_string)-1] = '\x0';
			error[e++].message = (char *)strdup(error_string);
		}
		if (commands[x].description != NULL && strchr(commands[x].description, ';')) {
			snprintf(error_string, sizeof(error_string), "主机\"%s\"上的服务描述\"%s\"包含分号", commands[x].description, commands[x].host_name);
			error_string[sizeof(error_string)-1] = '\x0';
			error[e++].message = strdup(error_string);
		}
	}
	if (hostgroup_name && strchr(hostgroup_name, ';'))
		error[e++].message = strdup("主机组名包含分号");
	if (servicegroup_name && strchr(servicegroup_name, ';'))
		error[e++].message = strdup("服务组名包含分号");

	printf("<BR><DIV align='center'>\n");

	/* if Icinga isn't checking external commands, don't do anything... */
	if (check_external_commands == FALSE) {
		print_generic_error_message("对不起,%s目前没有对额外命令进行检查，所以你的命令无法提交!","阅读关于如何启用额外命令的信息文档...", 2);

		return;
	}

	/* to be safe, we are going to REQUIRE that the authentication functionality is enabled... */
	if (use_authentication == FALSE) {
		print_generic_error_message("亲爱的对不起,您不能这样做...","可能是CGIs的认证功能没有开启. 在没有认证的情况下,允许未经授权的用户执行命令,Icinga将不能保证结果的正确行, 如果你确实想在无认证的情况下使用这个功能,你必须禁用此保护措施.在线的HTML帮助里,有关于CGI认证权相关的设置信息以及为何你需要设置认证的内容.", 2);

		return;
	}

	/* Check if we found errors which preventing us from submiting the command */
	if (e > 0) {
		printf("<DIV CLASS='errorBox'>\n");
		printf("<DIV CLASS='errorMessage'><table cellspacing=0 cellpadding=0 border=0><tr><td width=55><img src=\"%s%s\" border=0></td>", url_images_path, CMD_STOP_ICON);
		printf("<td CLASS='errorMessage'>发生如下错误.</td></tr></table></DIV>\n");
		printf("<table cellspacing=0 cellpadding=0 border=0 class='errorTable'>\n");
		for (e = 0; e < NUMBER_OF_STRUCTS; e++) {
			if (error[e].message == NULL)
				continue;
			printf("<tr><td class='errorString'>错误:</td><td class='errorContent'>%s</td></tr>\n", error[e].message);
		}
		printf("</table>\n</DIV>\n");
		printf("<BR>\n");
		printf("<table cellspacing=0 cellpadding=0 border=0 class='BoxWidth'><tr>\n");
		printf("<td align='left' width='50%%'><input type='submit' value='< 返回并修复' onClick='window.history.go(-1);' class='submitButton'></td>\n");
		printf("<td align='right' width='50%%'><input type='submit' value='离开这里' onClick='window.history.go(-2);' class='submitButton'></td>\n");
		printf("</tr></table></DIV>");
		return;
	}

	/* Let's see if we have a command witch dosn't have any host, services or downtime/comment id's and check the authorisation */
	if (cmd_has_objects == FALSE && is_authorized[0] == FALSE) {
		print_generic_error_message("对不起，您无权限提交指定命令.","阅读关于CGIs认证和授权的文档部分，以获取更多信息.", 2);

		return;
	}

	/* everything looks okay, so let's go ahead and commit the command... */
	commit_command(cmd);

	/* for commands without objects get the first result*/
	if (cmd_has_objects == FALSE) {
		if (submit_result[0] == OK) {
			printf("<DIV CLASS='successBox'>\n");
			printf("<DIV CLASS='successMessage'>\n");
				printf("<DIV CLASS='successMessage'>您的命令请求已成功提交给%s处理.<BR><BR>\n", PROGRAM_NAME);
				printf("备注：实际上处理该命令还需要一定时间.</DIV>\n");
				printf("</DIV>\n");
				printf("<BR><input type='submit' value='完成' onClick='window.history.go(-2);' class='submitButton'></DIV>\n");
		} else {
			print_generic_error_message("试图处理您提交的命令时发生错误.","不幸的是，现在还不能确定这个问题的根本原因.", 2);
		}
	} else {
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (cmd == CMD_DEL_HOST_COMMENT || cmd == CMD_DEL_SVC_COMMENT || cmd == CMD_DEL_HOST_DOWNTIME || cmd == CMD_DEL_SVC_DOWNTIME) {
				if (multi_ids[x] == FALSE)
					continue;
			} else {
				if (commands[x].host_name == NULL)
					continue;
			}

			if (is_authorized[x] == FALSE || submit_result[x] == ERROR) {
				error_found = TRUE;
				break;
			}
		}

		if (error_found) {
			print_generic_error_message("当试图处理您提交的命令时发生错误.","并非所有的命令能够成功发送...", 0);
		} else {
			printf("<DIV CLASS='successBox'>\n");
			printf("<DIV CLASS='successMessage'>您的命令请求已成功提交给%s处理.<BR><BR>\n", PROGRAM_NAME);
			printf("备注：实际上处理该命令还需要一定时间.</DIV>\n");
			printf("</DIV>\n");
		}

		printf("<BR>\n");
		printf("<TABLE CELLSPACING='0' CELLPADDING=0 BORDER=0 CLASS='BoxWidth'>\n");
		printf("<tr class='BoxWidth'><td width='33%%'></td><td width='33%%' align='center'><input type='submit' value='完成' onClick='window.history.go(-2);' class='submitButton'></td><td width='33%%' align='right'>\n");
		if (!error_found)
			printf("<input type='submit' value='让我看看都做了什么' onClick=\"document.getElementById('sumCommit').style.display = '';\" class='submitButton'>\n");
		printf("</td></TR></TABLE>\n");
		printf("<BR><BR>\n");

		printf("<TABLE CELLSPACING='0' CELLPADDING='0' ID='sumCommit' %s><TR><TD CLASS='boxFrame BoxWidth'>\n", (error_found) ? "" : "style='display:none;'");
		printf("<table cellspacing=2 cellpadding=0 border=0 class='contentTable'>\n");
		if (cmd == CMD_DEL_HOST_COMMENT || cmd == CMD_DEL_SVC_COMMENT)
			printf("<tr class='sumHeader'><td width='80%%'>注释ID</td><td width='20%%'>Status</td></tr>\n");
		else if (cmd == CMD_DEL_HOST_DOWNTIME || cmd == CMD_DEL_SVC_DOWNTIME)
			printf("<tr class='sumHeader'><td width='80%%'>宕机ID</td><td width='20%%'>Status</td></tr>\n");
		else
			printf("<tr class='sumHeader'><td width='40%%'>主机</td><td width='40%%'>服务</td><td width='20%%'>状态</td></tr>\n");

		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {

			if (cmd == CMD_DEL_HOST_COMMENT || cmd == CMD_DEL_SVC_COMMENT || cmd == CMD_DEL_HOST_DOWNTIME || cmd == CMD_DEL_SVC_DOWNTIME) {
				if (multi_ids[x] == FALSE)
					continue;
				row_color = (row_color == 0) ? 1 : 0;
				printf("<tr class='status%s'><td>%lu</td><td>", (row_color == 0) ? "Even" : "Odd ", multi_ids[x]);
			} else {
				if (commands[x].host_name == NULL)
					continue;
				row_color = (row_color == 0) ? 1 : 0;

				printf("<tr class='status%s'><td>%s</td><td>%s</td><td>", (row_color == 0) ? "Even" : "Odd ", commands[x].host_name, (commands[x].description != NULL) ? commands[x].description : "N/A");
			}
			if (is_authorized[x] == FALSE)
				printf("<DIV class='commitFailed'>未授权</DIV>");
			else if (submit_result[x] == ERROR)
				printf("<DIV class='commitFailed'>失败</DIV>");
			else if (submit_result[x] == OK)
				printf("<DIV class='commitSuccess'>成功</DIV>");
			else
				printf("<DIV class='commitUnknown'>未知</DIV>");

			printf("</TD><TR>\n");
		}
		printf("</TABLE>\n");
		printf("</TD></TR></TABLE></DIV>\n");
	}
	return;
}


/** @brief doe's some checks before passing data to write_command_to_file
 *
 *  Actually defines the command cmd_submitf.
**/
__attribute__((format(printf, 2, 3)))
static int cmd_submitf(int id, const char *fmt, ...) {
	char cmd[MAX_EXTERNAL_COMMAND_LENGTH];
	const char *command;
	int len, len2;
	va_list ap;

	command = extcmd_get_name(id);

	/*
	 * We disallow sending 'CHANGE' commands from the cgi's
	 * until we do proper session handling to prevent cross-site
	 * request forgery
	 * 2012-04-23 MF: Allow those and do proper checks on the cmds
	 * for changed mod attr
	 */
	/*if (!command || (strlen(command) > 6 && !memcmp("CHANGE", command, 6)))
		return ERROR;
	*/

	len = snprintf(cmd, sizeof(cmd) - 1, "[%lu] %s;", time(NULL), command);

	if (len < 0 || len >= sizeof(cmd))
		return ERROR;

	if (fmt) {
		va_start(ap, fmt);
		len2 = vsnprintf(&cmd[len], sizeof(cmd) - len - 1, fmt, ap);
		va_end(ap);
		if (len2 < 0 || len2 >= sizeof(cmd) - len)
			return ERROR;
	}

	return write_command_to_file(cmd);
}

int commit_command(int cmd) {
	time_t current_time;
	time_t scheduled_time;
	time_t notification_time;
	char *temp_buffer = NULL;
	int x = 0, dummy;

	/* get the current time */
	time(&current_time);

	/* get the scheduled time */
	scheduled_time = current_time + (schedule_delay * 60);

	/* get the notification time */
	notification_time = current_time + (notification_delay * 60);

	/* decide how to form the command line... */
	switch (cmd) {

		/* commands without arguments */
	case CMD_START_EXECUTING_SVC_CHECKS:
	case CMD_STOP_EXECUTING_SVC_CHECKS:
	case CMD_START_ACCEPTING_PASSIVE_SVC_CHECKS:
	case CMD_STOP_ACCEPTING_PASSIVE_SVC_CHECKS:
	case CMD_ENABLE_EVENT_HANDLERS:
	case CMD_DISABLE_EVENT_HANDLERS:
	case CMD_START_OBSESSING_OVER_SVC_CHECKS:
	case CMD_STOP_OBSESSING_OVER_SVC_CHECKS:
	case CMD_ENABLE_FLAP_DETECTION:
	case CMD_DISABLE_FLAP_DETECTION:
	case CMD_ENABLE_FAILURE_PREDICTION:
	case CMD_DISABLE_FAILURE_PREDICTION:
	case CMD_ENABLE_PERFORMANCE_DATA:
	case CMD_DISABLE_PERFORMANCE_DATA:
	case CMD_START_EXECUTING_HOST_CHECKS:
	case CMD_STOP_EXECUTING_HOST_CHECKS:
	case CMD_START_ACCEPTING_PASSIVE_HOST_CHECKS:
	case CMD_STOP_ACCEPTING_PASSIVE_HOST_CHECKS:
	case CMD_START_OBSESSING_OVER_HOST_CHECKS:
	case CMD_STOP_OBSESSING_OVER_HOST_CHECKS:
		if (is_authorized[x])
			submit_result[x] = cmd_submitf(cmd, NULL);
		break;

		/* simple host commands */
	case CMD_ENABLE_HOST_FLAP_DETECTION:
	case CMD_DISABLE_HOST_FLAP_DETECTION:
	case CMD_ENABLE_PASSIVE_HOST_CHECKS:
	case CMD_DISABLE_PASSIVE_HOST_CHECKS:
	case CMD_START_OBSESSING_OVER_HOST:
	case CMD_STOP_OBSESSING_OVER_HOST:
	case CMD_DEL_ALL_HOST_COMMENTS:
	case CMD_ENABLE_ALL_NOTIFICATIONS_BEYOND_HOST:
	case CMD_DISABLE_ALL_NOTIFICATIONS_BEYOND_HOST:
	case CMD_ENABLE_HOST_EVENT_HANDLER:
	case CMD_DISABLE_HOST_EVENT_HANDLER:
	case CMD_ENABLE_HOST_CHECK:
	case CMD_DISABLE_HOST_CHECK:
	case CMD_REMOVE_HOST_ACKNOWLEDGEMENT:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s", commands[x].host_name);
		}
		break;

		/* simple service commands */
	case CMD_ENABLE_SVC_FLAP_DETECTION:
	case CMD_DISABLE_SVC_FLAP_DETECTION:
	case CMD_ENABLE_PASSIVE_SVC_CHECKS:
	case CMD_DISABLE_PASSIVE_SVC_CHECKS:
	case CMD_START_OBSESSING_OVER_SVC:
	case CMD_STOP_OBSESSING_OVER_SVC:
	case CMD_DEL_ALL_SVC_COMMENTS:
	case CMD_ENABLE_SVC_NOTIFICATIONS:
	case CMD_DISABLE_SVC_NOTIFICATIONS:
	case CMD_ENABLE_SVC_EVENT_HANDLER:
	case CMD_DISABLE_SVC_EVENT_HANDLER:
	case CMD_ENABLE_SVC_CHECK:
	case CMD_DISABLE_SVC_CHECK:
	case CMD_REMOVE_SVC_ACKNOWLEDGEMENT:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s;%s", commands[x].host_name, commands[x].description);
		}
		break;

	case CMD_ADD_HOST_COMMENT:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s;%d;%s;%s", commands[x].host_name, persistent_comment, comment_author, comment_data);
		}
		break;

	case CMD_ADD_SVC_COMMENT:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s;%s;%d;%s;%s", commands[x].host_name, commands[x].description, persistent_comment, comment_author, comment_data);
		}
		break;

	case CMD_DEL_HOST_COMMENT:
	case CMD_DEL_SVC_COMMENT:
	case CMD_DEL_HOST_DOWNTIME:
	case CMD_DEL_SVC_DOWNTIME:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (multi_ids[x] == FALSE)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%lu", multi_ids[x]);
		}
		break;

	case CMD_DEL_DOWNTIME_BY_HOST_NAME:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s", commands[x].host_name);
		}
		break;

	case CMD_DELAY_HOST_NOTIFICATION:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s;%lu", commands[x].host_name, notification_time);
		}
		break;

	case CMD_DELAY_SVC_NOTIFICATION:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s;%s;%lu", commands[x].host_name, commands[x].description, notification_time);
		}
		break;

	case CMD_SCHEDULE_SVC_CHECK:
	case CMD_SCHEDULE_FORCED_SVC_CHECK:
		if (force_check == TRUE)
			cmd = CMD_SCHEDULE_FORCED_SVC_CHECK;
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s;%s;%lu", commands[x].host_name, commands[x].description, start_time);
		}
		break;

	case CMD_ENABLE_NOTIFICATIONS:
	case CMD_SHUTDOWN_PROCESS:
	case CMD_RESTART_PROCESS:
		if (is_authorized[x])
			submit_result[x] = cmd_submitf(cmd, "%lu", scheduled_time);
		break;

	case CMD_DISABLE_NOTIFICATIONS:
		if (is_authorized[x]) {
			/* we should expire the disabled notifications */
			if(end_time > 0) {
				cmd = CMD_DISABLE_NOTIFICATIONS_EXPIRE_TIME;
				submit_result[x] = cmd_submitf(cmd, "%lu;%lu", scheduled_time, end_time);
				my_free(temp_buffer);
			} else {
				submit_result[x] = cmd_submitf(cmd, "%lu", scheduled_time);
			}
		}
		break;

	case CMD_ENABLE_HOST_SVC_CHECKS:
	case CMD_DISABLE_HOST_SVC_CHECKS:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s", commands[x].host_name);
		}
		if (affect_host_and_services == TRUE) {
			cmd = (cmd == CMD_ENABLE_HOST_SVC_CHECKS) ? CMD_ENABLE_HOST_CHECK : CMD_DISABLE_HOST_CHECK;
			for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
				if (commands[x].host_name == NULL)
					continue;
				if (is_authorized[x])
					submit_result[x] |= cmd_submitf(cmd, "%s", commands[x].host_name);
			}
		}
		break;

	case CMD_SCHEDULE_HOST_SVC_CHECKS:
		if (force_check == TRUE)
			cmd = CMD_SCHEDULE_FORCED_HOST_SVC_CHECKS;
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s;%lu", commands[x].host_name, scheduled_time);
		}
		break;

	case CMD_ENABLE_HOST_NOTIFICATIONS:
	case CMD_DISABLE_HOST_NOTIFICATIONS:
		if (propagate_to_children == TRUE)
			cmd = (cmd == CMD_ENABLE_HOST_NOTIFICATIONS) ? CMD_ENABLE_HOST_AND_CHILD_NOTIFICATIONS : CMD_DISABLE_HOST_AND_CHILD_NOTIFICATIONS;
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s", commands[x].host_name);
		}
		break;

	case CMD_ENABLE_HOST_SVC_NOTIFICATIONS:
	case CMD_DISABLE_HOST_SVC_NOTIFICATIONS:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s", commands[x].host_name);
		}
		if (affect_host_and_services == TRUE) {
			cmd = (cmd == CMD_ENABLE_HOST_SVC_NOTIFICATIONS) ? CMD_ENABLE_HOST_NOTIFICATIONS : CMD_DISABLE_HOST_NOTIFICATIONS;
			for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
				if (commands[x].host_name == NULL)
					continue;
				if (is_authorized[x])
					submit_result[x] |= cmd_submitf(cmd, "%s", commands[x].host_name);
			}
		}
		break;

	case CMD_ACKNOWLEDGE_HOST_PROBLEM:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x]) {
				if (end_time > 0) {
					cmd = CMD_ACKNOWLEDGE_HOST_PROBLEM_EXPIRE;
					dummy = asprintf(&temp_buffer, "%s - 确认到期: %s.", comment_data, end_time_string);
					submit_result[x] = cmd_submitf(cmd, "%s;%d;%d;%d;%lu;%s;%s", commands[x].host_name, (sticky_ack == TRUE) ? ACKNOWLEDGEMENT_STICKY : ACKNOWLEDGEMENT_NORMAL, send_notification, persistent_comment, end_time, comment_author, temp_buffer);
					my_free(temp_buffer);
				} else
					submit_result[x] = cmd_submitf(cmd, "%s;%d;%d;%d;%s;%s", commands[x].host_name, (sticky_ack == TRUE) ? ACKNOWLEDGEMENT_STICKY : ACKNOWLEDGEMENT_NORMAL, send_notification, persistent_comment, comment_author, comment_data);
			}
		}
		break;

	case CMD_ACKNOWLEDGE_SVC_PROBLEM:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x]) {
				if (end_time > 0) {
					cmd = CMD_ACKNOWLEDGE_SVC_PROBLEM_EXPIRE;
					dummy = asprintf(&temp_buffer, "%s - 确认到期: %s.", comment_data, end_time_string);
					submit_result[x] = cmd_submitf(cmd, "%s;%s;%d;%d;%d;%lu;%s;%s", commands[x].host_name, commands[x].description, (sticky_ack == TRUE) ? ACKNOWLEDGEMENT_STICKY : ACKNOWLEDGEMENT_NORMAL, send_notification, persistent_comment, end_time, comment_author, temp_buffer);
					my_free(temp_buffer);
				} else
					submit_result[x] = cmd_submitf(cmd, "%s;%s;%d;%d;%d;%s;%s", commands[x].host_name, commands[x].description, (sticky_ack == TRUE) ? ACKNOWLEDGEMENT_STICKY : ACKNOWLEDGEMENT_NORMAL, send_notification, persistent_comment, comment_author, comment_data);
			}
		}
		break;

	case CMD_PROCESS_SERVICE_CHECK_RESULT:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s;%s;%d;%s|%s", commands[x].host_name, commands[x].description, plugin_state, plugin_output, performance_data);
		}
		break;

	case CMD_PROCESS_HOST_CHECK_RESULT:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s;%d;%s|%s", commands[x].host_name, plugin_state, plugin_output, performance_data);
		}
		break;

	case CMD_SCHEDULE_HOST_DOWNTIME:
		if (child_options == 1)
			cmd = CMD_SCHEDULE_AND_PROPAGATE_TRIGGERED_HOST_DOWNTIME;
		else if (child_options == 2)
			cmd = CMD_SCHEDULE_AND_PROPAGATE_HOST_DOWNTIME;
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s;%lu;%lu;%d;%lu;%lu;%s;%s", commands[x].host_name, start_time, end_time, fixed, triggered_by, duration, comment_author, comment_data);
		}
		break;

	case CMD_SCHEDULE_HOST_SVC_DOWNTIME:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s;%lu;%lu;%d;%lu;%lu;%s;%s", commands[x].host_name, start_time, end_time, fixed, triggered_by, duration, comment_author, comment_data);
		}
		break;

	case CMD_SCHEDULE_SVC_DOWNTIME:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s;%s;%lu;%lu;%d;%lu;%lu;%s;%s", commands[x].host_name, commands[x].description, start_time, end_time, fixed, triggered_by, duration, comment_author, comment_data);
		}
		break;

	case CMD_SCHEDULE_HOST_CHECK:
		if (force_check == TRUE)
			cmd = CMD_SCHEDULE_FORCED_HOST_CHECK;
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s;%lu", commands[x].host_name, start_time);
		}
		break;

	case CMD_SEND_CUSTOM_HOST_NOTIFICATION:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s;%d;%s;%s", commands[x].host_name, (force_notification | broadcast_notification), comment_author, comment_data);
		}
		break;

	case CMD_SEND_CUSTOM_SVC_NOTIFICATION:
		for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
			if (commands[x].host_name == NULL)
				continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s;%s;%d;%s;%s", commands[x].host_name, commands[x].description, (force_notification | broadcast_notification), comment_author, comment_data);
		}
		break;


		/***** HOSTGROUP COMMANDS *****/

	case CMD_ENABLE_HOSTGROUP_SVC_NOTIFICATIONS:
	case CMD_DISABLE_HOSTGROUP_SVC_NOTIFICATIONS:
		if (is_authorized[x])
			submit_result[x] = cmd_submitf(cmd, "%s", hostgroup_name);
		if (affect_host_and_services == TRUE) {
			cmd = (cmd == CMD_ENABLE_HOSTGROUP_SVC_NOTIFICATIONS) ? CMD_ENABLE_HOSTGROUP_HOST_NOTIFICATIONS : CMD_DISABLE_HOSTGROUP_HOST_NOTIFICATIONS;
			if (is_authorized[x])
				submit_result[x] |= cmd_submitf(cmd, "%s", hostgroup_name);
		}
		break;

	case CMD_ENABLE_HOSTGROUP_HOST_NOTIFICATIONS:
	case CMD_DISABLE_HOSTGROUP_HOST_NOTIFICATIONS:
		if (is_authorized[x])
			submit_result[x] = cmd_submitf(cmd, "%s", hostgroup_name);
		break;

	case CMD_ENABLE_HOSTGROUP_SVC_CHECKS:
	case CMD_DISABLE_HOSTGROUP_SVC_CHECKS:
		if (is_authorized[x])
			submit_result[x] = cmd_submitf(cmd, "%s", hostgroup_name);
		if (affect_host_and_services == TRUE) {
			cmd = (cmd == CMD_ENABLE_HOSTGROUP_SVC_CHECKS) ? CMD_ENABLE_HOSTGROUP_HOST_CHECKS : CMD_DISABLE_HOSTGROUP_HOST_CHECKS;
			if (is_authorized[x])
				submit_result[x] |= cmd_submitf(cmd, "%s", hostgroup_name);
		}
		break;

	case CMD_SCHEDULE_HOSTGROUP_HOST_DOWNTIME:
		if (is_authorized[x])
			submit_result[x] = cmd_submitf(cmd, "%s;%lu;%lu;%d;0;%lu;%s;%s", hostgroup_name, start_time, end_time, fixed, duration, comment_author, comment_data);
		break;

	case CMD_SCHEDULE_HOSTGROUP_SVC_DOWNTIME:
		if (is_authorized[x])
			submit_result[x] = cmd_submitf(cmd, "%s;%lu;%lu;%d;0;%lu;%s;%s", hostgroup_name, start_time, end_time, fixed, duration, comment_author, comment_data);
		if (affect_host_and_services == TRUE) {
			if (is_authorized[x])
				submit_result[x] |= cmd_submitf(CMD_SCHEDULE_HOSTGROUP_HOST_DOWNTIME, "%s;%lu;%lu;%d;0;%lu;%s;%s", hostgroup_name, start_time, end_time, fixed, duration, comment_author, comment_data);
		}
		break;


		/***** SERVICEGROUP COMMANDS *****/

	case CMD_ENABLE_SERVICEGROUP_SVC_NOTIFICATIONS:
	case CMD_DISABLE_SERVICEGROUP_SVC_NOTIFICATIONS:
		if (is_authorized[x])
			submit_result[x] = cmd_submitf(cmd, "%s", servicegroup_name);
		if (affect_host_and_services == TRUE) {
			cmd = (cmd == CMD_ENABLE_SERVICEGROUP_SVC_NOTIFICATIONS) ? CMD_ENABLE_SERVICEGROUP_HOST_NOTIFICATIONS : CMD_DISABLE_SERVICEGROUP_HOST_NOTIFICATIONS;
			if (is_authorized[x])
				submit_result[x] |= cmd_submitf(cmd, "%s", servicegroup_name);
		}
		break;

	case CMD_ENABLE_SERVICEGROUP_HOST_NOTIFICATIONS:
	case CMD_DISABLE_SERVICEGROUP_HOST_NOTIFICATIONS:
		if (is_authorized[x])
			submit_result[x] = cmd_submitf(cmd, "%s", servicegroup_name);
		break;

	case CMD_ENABLE_SERVICEGROUP_SVC_CHECKS:
	case CMD_DISABLE_SERVICEGROUP_SVC_CHECKS:
		if (is_authorized[x])
			submit_result[x] = cmd_submitf(cmd, "%s", servicegroup_name);
		if (affect_host_and_services == TRUE) {
			cmd = (cmd == CMD_ENABLE_SERVICEGROUP_SVC_CHECKS) ? CMD_ENABLE_SERVICEGROUP_HOST_CHECKS : CMD_DISABLE_SERVICEGROUP_HOST_CHECKS;
			if (is_authorized[x])
				submit_result[x] |= cmd_submitf(cmd, "%s", servicegroup_name);
		}
		break;

	case CMD_SCHEDULE_SERVICEGROUP_HOST_DOWNTIME:
		if (is_authorized[x])
			submit_result[x] = cmd_submitf(cmd, "%s;%lu;%lu;%d;0;%lu;%s;%s", servicegroup_name, start_time, end_time, fixed, duration, comment_author, comment_data);
		break;

	case CMD_SCHEDULE_SERVICEGROUP_SVC_DOWNTIME:
		if (is_authorized[x])
			submit_result[x] = cmd_submitf(cmd, "%s;%lu;%lu;%d;0;%lu;%s;%s", servicegroup_name, start_time, end_time, fixed, duration, comment_author, comment_data);
		if (affect_host_and_services == TRUE) {
			if (is_authorized[x])
				submit_result[x] |= cmd_submitf(CMD_SCHEDULE_SERVICEGROUP_HOST_DOWNTIME, "%s;%lu;%lu;%d;0;%lu;%s;%s", servicegroup_name, start_time, end_time, fixed, duration, comment_author, comment_data);
		}
		break;

        case CMD_CHANGE_HOST_MODATTR:
                for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
                        if (commands[x].host_name == NULL)
                                continue;

			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s;%lu", commands[x].host_name, attr);
		}
		break;

        case CMD_CHANGE_SVC_MODATTR:
                for (x = 0; x < NUMBER_OF_STRUCTS; x++) {
                        if (commands[x].host_name == NULL)
                                continue;
			if (is_authorized[x])
				submit_result[x] = cmd_submitf(cmd, "%s;%s;%lu", commands[x].host_name, commands[x].description, attr);
		}
		break;

	default:
		submit_result[x] = ERROR;
		break;
	}

	return OK;
}

int write_command_to_file(char *cmd) {
	char *buffer;
	char *ip_address;
	int dummy;
	char *p;
	FILE *fp;
	struct stat statbuf;
	char error_string[MAX_INPUT_BUFFER];

	/*
	 * Commands are not allowed to have newlines in them, as
	 * that allows malicious users to hand-craft requests that
	 * bypass the access-restrictions.
	 */
	if (!cmd || !*cmd || strchr(cmd, '\n'))
		return ERROR;

	/* bail out if the external command file doesn't exist */
	if (stat(command_file, &statbuf)) {
		snprintf(error_string, sizeof(error_string), "错误: 无法stat()命令文件'%s'!", command_file);
		error_string[sizeof(error_string)-1] = '\x0';

		print_generic_error_message(error_string, "额外命令文件可能会丢失,Icinga可能没有运行, /或Icinga无法检查额外命令.", 2);

		return ERROR;
	}

	/* open the command for writing (since this is a pipe, it will really be appended) */
	fp = fopen(command_file, "w");
	if (fp == NULL) {
		snprintf(error_string, sizeof(error_string), "错误: 无法打开要更新的命令文件'%s'!", command_file);
		error_string[sizeof(error_string)-1] = '\x0';

		print_generic_error_message(error_string, "额外命令文件的权限和/或目录可能不正确.请参考FAQ设置正确的权限.", 2);

		return ERROR;
	}

	if (use_logging == TRUE) {
		// find closing bracket in cmd line
		p = strchr(cmd, ']');
		// if found get everything after closing bracket
		if (p != NULL)
			p += 2;
		else	// get complete command line
			p = &cmd[0];

		/* get remote address */
		ip_address = strdup(getenv("REMOTE_ADDR"));

		/* construct log entry */
		dummy = asprintf(&buffer, "额外命令: %s;%s;%s", current_authdata.username, (ip_address != NULL) ? ip_address : "未知的远端地址", p);

		/* write command to cgi log */
		write_to_cgi_log(buffer);

		/* log comments if forced */
		if (enforce_comments_on_actions == TRUE) {
			my_free(buffer);
			dummy = asprintf(&buffer, "强迫注释: %s;%s;%s;%s", current_authdata.username, (ip_address != NULL) ? ip_address : "未知的远端地址", comment_author, comment_data);
			write_to_cgi_log(buffer);
		}
		my_free(buffer);
	}

	/* write the command to file */
	fprintf(fp, "%s\n", cmd);

	/* flush buffer */
	fflush(fp);

	fclose(fp);

	return OK;
}

void clean_comment_data(char *buffer) {
	int x;
	int y;

	y = (int)strlen(buffer);

	for (x = 0; x < y; x++) {
		if (buffer[x] == ';' || buffer[x] == '\n' || buffer[x] == '\r')
			buffer[x] = ' ';
	}

	return;
}

void check_comment_sanity(int *e) {
	if (!strcmp(comment_author, ""))
		error[(*e)++].message = strdup("没有输入编辑者名称");
	if (!strcmp(comment_data, ""))
		error[(*e)++].message = strdup("没有输入注释数据");

	return;
}

void check_time_sanity(int *e) {
	if (start_time == (time_t)0)
		error[(*e)++].message = strdup("开始时间不能为零或无法正确识别的日期格式");
	if (end_time==(time_t)0)
		error[(*e)++].message = strdup("结束时间不能为零或无法正确识别的日期格式");
	if (end_time<start_time)
		error[(*e)++].message = strdup("开始日期早于结束日期");

	return;
}
