#' Login server module.
#'
#' This is the main server logic for the `login` Shiny module to be included
#' in server.R side,.
#'
#' @param id unique ID for the Shiny Login module.
#' @param db_conn a DBI database connection.
#' @param users_table the name of the table in the database to store credentials.
#' @param activity_table the name of the table in the database to log login and
#'        logout activity.
#' @param emailer function used to send email messages. The function should have
#'        have three parameters: `to_email` for the address to send the email,
#'        `subject` for the subject of the email and `message` for the contents
#'        of the email address. See [emayili_emailer()] for an example.
#' @param reset_password_subject the subject of password reset emails.
#' @param new_account_subject the subject used for verifying new accounts.
#' @param verify_email if true new accounts will need to verify their email
#'        address before the account is crated. This is done by sending a six
#'        digit code to the email address.
#' @param additional_fields a character vector of additional fields the user is
#'        asked to fill in at the when creating a new account. The names of the
#'        vector correspond to the variable names and the values will be used
#'        as the input labels.
#' @param username_label label used for text inputs of username.
#' @param password_label label used for text inputs of password.
#' @param create_account_label label for the create account button.
#' @param cookie_name the name of the cookie saved. Set to `NULL` to disable cookies.
#' @param cookie_expiration the number of days after which the cookie will expire.
#' @param cookie_password password used to encrypt cookies saved in the browser.
#' @param create_account_message Email message sent to confirm email when creating
#'        a new account. Include `\%s` somewhere in the message to include the code.
#' @param reset_email_message Email message sent to reset password. Include `\%s`
#'        somewhere in the message to include the code.
#' @param enclosing_panel the Shiny element that contains all the UI elements.
#'        The default is [shiny::wellPanel()]. If you wish a more subtle appearance
#'        [htmltools::div()] is a reasonable choice.
#' @param code_length the number of digits of codes emailed for creating accounts
#'        (if `verify_email == TRUE`) or resetting passwords.
#' @param salt a salt to use to encrypt the password before storing it in the database.
#' @param salt_algo the algorithm used to encrypt the password. See
#'        [digest::digest()] for more details.
#' @param shinybusy_position Position of the spinner when sending emails.
#'        See [shinybusy::use_busy_spinner()] for more information.
#' @param shinybusy_spin Style of the spinner when sending emails.
#'        See [shinybusy::use_busy_spinner()] for more information.
#' @return a [shiny::reactiveValues()] object that includes two values: `logged_in`
#'        (this is TRUE if the user is logged in) and `username` which has the
#'        user's login username if logged in.
#' @import shiny
#' @importFrom DBI dbListTables dbWriteTable dbReadTable dbSendQuery dbFetch
#' @importFrom cookies get_cookie set_cookie
#' @importFrom stringr str_pad
#' @importFrom shinybusy use_busy_spinner show_spinner hide_spinner
#' @importFrom digest digest
#' @importFrom shinyjs hide show
#' @importFrom sodium data_decrypt data_encrypt sha256 bin2hex hex2bin
#' @export
#' @example inst/login_demo_simple/app.R
login_server <- function(
		id,
		db_conn = NULL,
		users_table = 'users',
		activity_table = 'users_activity',
		emailer = NULL,
		new_account_subject = 'Verifizieren Sie ihren neuen Account',
		reset_password_subject = 'Passwort zurücksetzen',
		verify_email = !is.null(emailer),
		additional_fields = NULL,
		cookie_name = 'loginusername',
		cookie_expiration = 30,
		cookie_password = NULL,
		username_label = 'E-Mail',
		password_label = 'Passwort',
		create_account_label = "Account erstellen",
		create_account_message = NULL,
		reset_email_message = NULL,
		enclosing_panel = shiny::wellPanel,
		code_length = 6,
		salt = NULL,
		salt_algo = "sha512",
		shinybusy_spin = "fading-circle",
		shinybusy_position = "full-page"
) {
	# Set defaults for email messages
	if(is.null(create_account_message)) {
		create_account_message <- 'Ihr Bestätigungscode zur Erstellung eines neuen Kontos lautet: %s\n
Wenn Sie nicht angefordert haben, ein neues Konto zu erstellen, können Sie diese E-Mail ignorieren.'
	}
	if(is.null(reset_email_message)) {
		reset_email_message <- 'Ihr Code zum Zurücksetzen des Passworts lautet: %s\n
Wenn Sie nicht angefordert haben, Ihr Passwort zurückzusetzen, können Sie diese E-Mail ignorieren..'
	}

	# Geheimer Schlüssel für die Verschlüsselung
	key <- charToRaw("1111111111111111")

	# Funktion zur Verschlüsselung von E-Mail-Adressen
	encrypt_email <- function(email) {
		encrypted <- aes_cbc_encrypt(charToRaw(email), key)
		hex_encrypted <- paste0(as.character(encrypted), collapse = "")
		return(hex_encrypted)
	}

	# Funktion zur Entschlüsselung von E-Mail-Adressen
	decrypt_email <- function(encrypted_email) {
		hex_raw <- as.raw(strtoi(strsplit(encrypted_email, NULL)[[1]], 16L))
		decrypted <- rawToChar(aes_cbc_decrypt(hex_raw, key))
		return(decrypted)
	}

	# Hash das Passwort mit Salt, wenn es bereitgestellt wurde
	get_password <- function(password) {
		if(is.null(salt)) {
			return(password)  # Kein Hashing, wenn kein Salt angegeben
		} else {
			return(digest::digest(paste0(salt, password), algo = salt_algo, serialize = FALSE))
		}
	}

	moduleServer(id, function(input, output, session) {
		# Initialize user data
		USER <- reactiveValues()
		USER$logged_in <- FALSE
		USER$unique <- format(Sys.time(), '%Y%m%d%H%M%S')
		USER$username <- NA
		for(i in additional_fields) {
			USER[[i]] <- NA
		}

		# Check for existing tables and create them if needed
		if(!users_table %in% DBI::dbListTables(db_conn)) {
			users <- data.frame(id = integer(), encrypted_email = character(),
								password = character(), created_date = numeric(),
								stringsAsFactors = FALSE)
			if(!is.null(additional_fields)) {
				for(i in seq_len(length(additional_fields))) {
					users[, names(additional_fields[i])] <- character()
				}
			}
			DBI::dbWriteTable(db_conn, users_table, users)
		}

		if(!activity_table %in% DBI::dbListTables(db_conn)) {
			activity <- data.frame(username = character(),
								   action = character(),
								   timestamp = numeric(),
								   stringsAsFactors = FALSE)
			DBI::dbWriteTable(db_conn, activity_table, activity)
		}

		# Functions for adding activity logs
		add_activitiy <- function(username, activity) {
			if(!is.null(activity_table)) {
				new_activity <- data.frame(username = username,
										   action = activity,
										   timestamp = Sys.time(),
										   stringsAsFactors = FALSE)
				DBI::dbWriteTable(db_conn, activity_table, new_activity, append = TRUE)
			}
		}

		get_users <- function() {
			DBI::dbReadTable(db_conn, users_table)
		}

		get_user <- function(username) {
			user <- DBI::dbSendQuery(db_conn, paste0("SELECT * FROM ", users_table, " WHERE encrypted_email='", username, "'")) |> DBI::dbFetch()
			return(user)
		}

		add_user <- function(newuser) {
			DBI::dbWriteTable(db_conn, users_table, newuser, append = TRUE)
		}

		# Handle user login
		login_message <- reactiveVal('')
		output$login_message <- renderText({
			login_message()
		})

		output$login_ui <- renderUI({
			args <- list(
				div(textOutput(NS(id, 'login_message')), style = 'color:red;'),
				textInput(NS(id, 'username'), label = username_label, value = ''),
				passwdInput(NS(id, 'password'), label = password_label, value = '')
			)

			args[[length(args) + 1]] <- actionButton(NS(id, "Login"), label = 'Login', value = TRUE)
			do.call(enclosing_panel, args)
		})

		observeEvent(input$Login, {
			users <- get_users()
			username <- input$username
			password <- get_password(input$password)

			# Entschlüsselung der E-Mail-Adresse
			encrypted_email <- encrypt_email(username)

			# Suche nach dem Benutzer
			Id.username <- which(users$encrypted_email == encrypted_email)
			if(length(Id.username) == 0) {
				login_message('Benutzername nicht gefunden.')
			} else if(password != users[Id.username,]$password) {
				login_message('Falsches Passwort.')
			} else {
				login_message('')
				USER$logged_in <- TRUE
				USER$username <- username
				for(i in names(additional_fields)) {
					USER[[i]] <- users[Id.username, i]
				}
				add_activitiy(username, 'login')

				# Set cookies if "Remember me" is checked
				if(!is.null(input$remember_me) && input$remember_me) {
					cookie_value <- username
					if(!is.null(cookie_key)) {
						cookie_value <- encrypt_cookie(username)
					}
					cookies::set_cookie(cookie_name = cookie_name, cookie_value = cookie_value, session = session, expiration = cookie_expiration)
				}
			}
		})

		# Handle user logout
		observeEvent(input$logout, {
			add_activitiy(USER$username, 'logout')
			USER$logged_in <- FALSE
			USER$username <- ''
			USER$unique <- format(Sys.time(), '%Y%m%d%H%M%S')
			for(i in names(additional_fields)) {
				USER[[i]] <- NA
			}
			if(!is.null(cookie_name)) {
				cookies::remove_cookie(cookie_name = cookie_name, session = session)
			}
		})

		# Handle new user registration
		observeEvent(input$new_user, {
			users <- get_users()
			username <- input$new_username
			password1 <- get_password(input$new_password1)
			password2 <- get_password(input$new_password2)

			if(password1 != password2) {
				new_user_message('Passwörter stimmen nicht überein.')
			} else {
				# Verschlüsselte E-Mail-Adresse speichern
				encrypted_email <- encrypt_email(username)

				# Speichern des neuen Benutzers mit verschlüsselter E-Mail
				newuser <- data.frame(
					encrypted_email = encrypted_email,
					password = password1,
					created_date = Sys.time(),
					stringsAsFactors = FALSE
				)
				if(!is.null(additional_fields)) {
					for(i in seq_len(length(additional_fields))) {
						newuser[1, names(additional_fields)[i]] <- input[[names(additional_fields)[i]]]
					}
				}
				add_user(newuser)
				add_activitiy(newuser[1,]$username, 'create_account')
				new_user_message(paste0('Neuer Account wurde erstellt für: ', username, '. Sie können sich nun einloggen.'))
			}
		})

		# Handle password reset
		observeEvent(input$reset_new_password, {
			if(input$reset_password1 == input$reset_password2) {
				# Passwort in der Datenbank zurücksetzen
				query <- paste0("UPDATE users SET password = '", get_password(input$reset_password1), "' WHERE encrypted_email = '", encrypt_email(input$username), "'")
				DBI::dbSendQuery(db_conn, query)
				add_activitiy(input$username, 'password_reset')
				reset_message('Passwort erfolgreich zurückgesetzt.')
			} else {
				reset_message('Die Passwörter stimmen nicht überein.')
			}
		})

		return(USER)
	})
}
