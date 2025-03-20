#' Login server module.
#'
#' This is the main server logic for the `login` Shiny module to be included
#' in server.R side,.
#'
#' @param id unique ID for the Shiny Login module.
#' @param db_conn a DBI database connection.
#' @param users_table the name of the table in the database to store credentials.
#' @param users_email_table the name of the table to store email verification data.
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
#' @param email_salt a salt to use for hashing email addresses.
#' @param email_salt_algo the algorithm used to hash email addresses.
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
		users_email_table = 'users_email',
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
		email_salt = NULL,
		email_salt_algo = "sha256",
		shinybusy_spin = "fading-circle",
		shinybusy_position = "full-page"
) {
	# Set defaults here since the parameter value is longer than 90 characters (fails CRAN CHECK)
	if(is.null(create_account_message)) {
		create_account_message <- 'Ihr Bestätigungscode zur Erstellung eines neuen Kontos lautet: %s\n
Wenn Sie nicht angefordert haben, ein neues Konto zu erstellen, können Sie diese E-Mail ignorieren.'
	}
	if(is.null(reset_email_message)) {
		reset_email_message <- 'Ihr Code zum Zurücksetzen des Passworts lautet: %s\n
Wenn Sie nicht angefordert haben, Ihr Passwort zurückzusetzen, können Sie diese E-Mail ignorieren..'
	}
	if(!is.null(additional_fields)) {
		if(is.null(names(additional_fields))) {
			names(additional_fields) <- additional_fields
		}
	}
	if(is.null(email_salt)) {
		warning("email_salt not specified. Email addresses will not be properly secured.")
		email_salt <- ""
	}

	cookie_key <- NULL
	# TODO: This is a workaround to the decryption. I am not entirely sure if this
	# compromises the encryption of the cookie value. See this issue:
	# https://github.com/r-lib/sodium/issues/21
	# Could make this a function parameter.
	cookie_nonce <- rep(as.raw(42), 24)

	encrypt_cookie <- function(message) {
		message |>
			charToRaw() |>
			sodium::data_encrypt(key = cookie_key, nonce = cookie_nonce) |>
			sodium::bin2hex()
	}

	decrypt_cookie <- function(message) {
		message |>
			sodium::hex2bin() |>
			sodium::data_decrypt(key = cookie_key, nonce = cookie_nonce) |>
			rawToChar()
	}

	if(!is.null(cookie_name)) {
		if(is.null(cookie_password)) {
			warning("cookie_password not specified. Not specifying a key file means cookies will be stored unencrypted in the user's browsers")
		} else {
			cookie_key <- sodium::sha256(charToRaw(cookie_password))
		}
	}

	moduleServer(id, function(input, output, session) {
		# Hash the email address to use as a unique identifier
		hash_email <- function(email) {
			digest::digest(paste0(email_salt, tolower(email)), algo = email_salt_algo, serialize = FALSE)
		}

		# Check to see if the users_table is already in the database, if not
		# create the table.
		if(!users_table %in% DBI::dbListTables(db_conn)) {
			users <- data.frame(user_id = character(),
								password = character(),
								created_date = numeric(),
								stringsAsFactors = FALSE)
			if(!is.null(additional_fields)) {
				for(i in seq_len(length(additional_fields))) {
					users[,names(additional_fields[i])] <- character()
				}
			}
			DBI::dbWriteTable(db_conn, users_table, users)
		}

		# Create the email verification table if it doesn't exist
		if(!users_email_table %in% DBI::dbListTables(db_conn)) {
			users_email <- data.frame(user_id = character(),
									  email = character(),
									  verified = logical(),
									  stringsAsFactors = FALSE)
			DBI::dbWriteTable(db_conn, users_email_table, users_email)
		}

		if(!activity_table %in% DBI::dbListTables(db_conn)) {
			activity <- data.frame(user_id = character(),
								   action = character(),
								   timestamp = numeric(),
								   stringsAsFactors = FALSE)
			DBI::dbWriteTable(db_conn, activity_table, activity)
		}

		get_password <- function(password) {
			if(is.null(salt)) {
				return(password)
			} else {
				return(digest::digest(paste0(salt, password), algo = salt_algo, serialize = FALSE))
			}
		}

		add_activitiy <- function(user_id, activity) {
			if(!is.null(activity_table)) {
				new_activity <- data.frame(user_id = user_id,
										   action = activity,
										   timestamp = Sys.time(),
										   stringsAsFactors = FALSE)
				DBI::dbWriteTable(db_conn, activity_table, new_activity, append = TRUE)
			}
		}

		get_users <- function() {
			DBI::dbReadTable(db_conn, users_table)
		}

		get_user_by_id <- function(user_id) {
			user <- DBI::dbSendQuery(
				db_conn,
				paste0("SELECT * FROM ", users_table, " WHERE user_id='", user_id, "'")
			) |> DBI::dbFetch()
			return(user)
		}

		get_user_by_email <- function(email) {
			email_hash <- hash_email(email)
			# First get the user_id from the email table
			user_id_query <- DBI::dbSendQuery(
				db_conn,
				paste0("SELECT user_id FROM ", users_email_table, " WHERE user_id='", email_hash, "'")
			) |> DBI::dbFetch()

			if(nrow(user_id_query) == 0) {
				return(data.frame())
			}

			# Then get the user data
			user <- DBI::dbSendQuery(
				db_conn,
				paste0("SELECT * FROM ", users_table, " WHERE user_id='", email_hash, "'")
			) |> DBI::dbFetch()

			return(user)
		}

		get_email_by_user_id <- function(user_id) {
			email_record <- DBI::dbSendQuery(
				db_conn,
				paste0("SELECT email FROM ", users_email_table, " WHERE user_id='", user_id, "'")
			) |> DBI::dbFetch()

			if(nrow(email_record) == 0) {
				return(NULL)
			}

			return(email_record$email[1])
		}

		add_user <- function(email, password, additional_data = NULL) {
			# Generate user_id from hashed email
			user_id <- hash_email(email)

			# Create user record
			new_user <- data.frame(
				user_id = user_id,
				password = password,
				created_date = Sys.time(),
				stringsAsFactors = FALSE
			)

			# Add additional fields if provided
			if(!is.null(additional_data)) {
				for(field_name in names(additional_data)) {
					new_user[1, field_name] <- additional_data[[field_name]]
				}
			}

			# Create email record
			new_email <- data.frame(
				user_id = user_id,
				email = email,
				verified = FALSE,
				stringsAsFactors = FALSE
			)

			# Insert records
			DBI::dbWriteTable(db_conn, users_table, new_user, append = TRUE)
			DBI::dbWriteTable(db_conn, users_email_table, new_email, append = TRUE)

			return(user_id)
		}

		set_email_verified <- function(user_id) {
			query <- paste0(
				"UPDATE ", users_email_table, " SET verified = TRUE WHERE user_id = '", user_id, "'"
			)
			DBI::dbSendQuery(db_conn, query)
		}

		generate_code <- function() {
			sample(10 ^ code_length - 1, size = 1) |>
				as.character() |>
				stringr::str_pad(width = code_length, pad = '0')
		}

		USER <- reactiveValues()
		USER$logged_in <- FALSE
		USER$unique <- format(Sys.time(), '%Y%m%d%H%M%S')
		USER$user_id <- NA
		USER$email <- NA
		for(i in additional_fields) {
			USER[[i]] <- NA
		}

		output$logged_in <- renderText({
			USER$logged_in
		})

		observeEvent(cookies::get_cookie(cookie_name = cookie_name, session = session), {
			cookie_value <- cookies::get_cookie(cookie_name = cookie_name, session = session)
			tryCatch({
				if(!is.null(cookie_key)) {
					user_id <- decrypt_cookie(cookie_value)
				} else {
					user_id <- cookie_value
				}
			}, error = function(e) {
				warning(paste0('Error retrieving cookie value.'))
				cookies::remove_cookie(cookie_name = cookie_name)
				return()
			})

			if(!is.null(user_id)) {
				user <- get_user_by_id(user_id)
				if(nrow(user) > 0) {
					USER$user_id <- user_id
					USER$email <- get_email_by_user_id(user_id)
					USER$logged_in <- TRUE
					for(i in names(additional_fields)) {
						USER[[i]] <- user[1,i]
					}
					add_activitiy(user_id, 'login_cookie')
				}
			}
		}, once = TRUE)

		##### User Login #######################################################
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

			args[[length(args) + 1]] <- actionButton(NS(id, "Login"),
													 label = 'Login',
													 value = TRUE)

			do.call(enclosing_panel, args)
		})

		observeEvent(input$Login, {
			email <- input$username
			password <- get_password(input$password)

			# Get user by email
			user <- get_user_by_email(email)

			if(nrow(user) == 0) {
				login_message('E-Mail nicht gefunden.')
			} else if(password != user$password) {
				login_message('Inkorrektes Passwort')
			} else {
				if(!is.null(input$remember_me)) {
					if(input$remember_me) {
						cookie_value <- user$user_id
						if(!is.null(cookie_key)) {
							cookie_value <- encrypt_cookie(user$user_id)
						}
						tryCatch({
							cookies::set_cookie(cookie_name = cookie_name,
												cookie_value = cookie_value,
												session = session,
												expiration = cookie_expiration)
						}, error = function(e) {
							message(e)
						})
					}
				}
				login_message('')
				USER$logged_in <- TRUE
				USER$user_id <- user$user_id
				USER$email <- email
				for(i in names(additional_fields)) {
					USER[[i]] <- user[i]
				}
				add_activitiy(user$user_id, 'login')
			}
		})

		##### User logout ######################################################
		observeEvent(input$logout, {
			add_activitiy(USER$user_id, 'logout')
			USER$logged_in <- FALSE
			USER$user_id <- NA
			USER$email <- NA
			USER$unique <- format(Sys.time(), '%Y%m%d%H%M%S')
			for(i in names(additional_fields)) {
				USER[[i]] <- NA
			}
			if(!is.null(cookie_name)) {
				tryCatch({
					cookies::remove_cookie(cookie_name = cookie_name, session = session)
				}, error = function(e) {
					message(e)
				})
			}
		})

		##### Create new user ##################################################
		new_user_message <- reactiveVal('')
		new_user_email <- reactiveVal('')
		new_user_password <- reactiveVal('')
		new_user_additional_data <- reactiveVal(list())
		new_user_code_verify <- reactiveVal('')

		output$new_user_message <- renderText({
			new_user_message()
		})

		output$new_user_ui <- renderUI({
			args <- list(
				div(textOutput(NS(id, 'new_user_message')), style = 'color:red;'),
				shinybusy::use_busy_spinner(spin = shinybusy_spin, position = shinybusy_position)
			)
			if(new_user_code_verify() == '') {
				args[[length(args) + 1]] <- textInput(inputId = NS(id, 'new_username'),
													  label = username_label, value = '')
				args[[length(args) + 1]] <- passwdInput(inputId = NS(id, 'new_password1'),
														label = password_label, value = '')
				args[[length(args) + 1]] <- passwdInput(inputId = NS(id, 'new_password2'),
														label = paste0(password_label, " bestätigen"), value = '')

				if(!is.null(additional_fields)) {
					for(i in seq_len(length(additional_fields))) {
						args[[length(args) + 1]] <- textInput(
							inputId = NS(id, names(additional_fields)[i]),
							label = additional_fields[i])
					}
				}

				args[[length(args) + 1]] <- actionButton(NS(id, "new_user"), create_account_label)
			} else {
				args[[length(args) + 1]] <- div(
					textInput(inputId = NS(id, 'new_user_code'),
							  label = 'Geben Sie den Code aus der E-Mail ein:',
							  value = '')
				)
				args[[length(args) + 1]] <- actionButton(inputId = NS(id, 'send_new_user_code'),
														 label = 'Code erneut senden')
				args[[length(args) + 1]] <- actionButton(inputId = NS(id, 'submit_new_user_code'),
														 label = 'Absenden')
			}

			do.call(enclosing_panel, args)
		})

		observeEvent(input$new_user, {
			email <- input$new_username
			password1 <- get_password(input$new_password1)
			password2 <- get_password(input$new_password2)

			# Check if email already exists (check by hashed email)
			user <- get_user_by_email(email)

			if(nrow(user) > 0) {
				new_user_message(paste0('Account exisitiert bereits für ', email))
			} else if(password1 != password2) {
				new_user_message('Passwörter stimmen nicht überein.')
			} else if(input$new_password1 == '') {
				# Check for a blank password
				new_user_message('Bitte geben Sie ein korrektes Passwort ein.')
			} else {
				# Store additional fields
				additional_data <- list()
				if(!is.null(additional_fields)) {
					for(i in seq_len(length(additional_fields))) {
						additional_data[[names(additional_fields)[i]]] <- input[[names(additional_fields)[i]]]
					}
				}

				if(verify_email) {
					shinybusy::show_spinner()
					new_user_email(email)
					new_user_password(password1)
					new_user_additional_data(additional_data)
					code <- generate_code()
					tryCatch({
						emailer(to_email = email,
								subject = new_account_subject,
								message = sprintf(create_account_message, code))
						new_user_code_verify(code)
					}, error = function(e) {
						message(e)
						new_user_message(paste0('Error sending email: ', as.character(e)))
					})
					shinybusy::hide_spinner()
				} else {
					# Directly create user without verification
					user_id <- add_user(email, password1, additional_data)
					set_email_verified(user_id)
					add_activitiy(user_id, 'create_account')
					new_user_message(paste0('Neuer Account wurde erstellt für: ', email,
											'. Sie können sich nun einloggen.'))
				}
			}
		})

		observeEvent(input$submit_new_user_code, {
			if(input$new_user_code == new_user_code_verify()) {
				email <- new_user_email()
				password <- new_user_password()
				additional_data <- new_user_additional_data()

				# Create the user
				user_id <- add_user(email, password, additional_data)
				set_email_verified(user_id)

				# Reset form state
				new_user_email('')
				new_user_password('')
				new_user_additional_data(list())
				new_user_code_verify('')

				new_user_message(paste0('Neuer Account wurde erstellt für: ', email,
										'. Sie können sich nun einloggen.'))
				add_activitiy(user_id, 'create_account')
			} else {
				new_user_message('Code ist nicht korrekt')
			}
		})

		observeEvent(input$send_new_user_code, {
			tryCatch({
				shinybusy::show_spinner()
				code <- generate_code()
				email <- new_user_email()
				emailer(to_email = email,
						subject = new_account_subject,
						message = sprintf(create_account_message, code))
				new_user_code_verify(code)
				new_user_message('Ein neue Code wurde versendet')
				shinybusy::hide_spinner()
			}, error = function(e) {
				message(e)
				new_user_message(paste0('Error sending email: ', as.character(e)))
			})
		})


		##### Reset password ###################################################
		reset_code <- reactiveVal('')
		reset_code_verify <- reactiveVal('')
		reset_message <- reactiveVal('')
		reset_user_id <- reactiveVal('')
		reset_email <- reactiveVal('')

		output$reset_password_ui <- renderUI({
			if(is.null(emailer)) {
				return(div('Email server has not been configured.'))
			}

			code <- isolate(input$reset_password_code)
			reset_password <- FALSE
			if(nchar(reset_code_verify()) == code_length) {
				if(code == reset_code()) {
					reset_password <- TRUE
				}
			}
			if(reset_code() == '') {
				enclosing_panel(
					shinybusy::use_busy_spinner(spin = shinybusy_spin, position = shinybusy_position),
					div(reset_message(), style = 'color:red'),
					div(
						textInput(inputId = NS(id, 'forgot_password_email'),
								  label = 'E-Mail Adresse: ',
								  value = '')),
					actionButton(inputId = NS(id, 'send_reset_password_code'),
								 label = 'Reset-Code senden')
				)
			} else if(reset_password) {
				enclosing_panel(
					shinybusy::use_busy_spinner(spin = shinybusy_spin, position = shinybusy_position),
					div(reset_message(), style = 'color:red'),
					div(
						passwdInput(inputId = NS(id, 'reset_password1'),
									label = 'Neues Passwort:',
									value = ''),
						passwdInput(inputId = NS(id, 'reset_password2'),
									label = 'Neues Passwort bestätigen:',
									value = '')
					),
					# br(),
					actionButton(inputId = NS(id, 'reset_new_password'),
								 label = 'Passwort zurücksetzen')
				)
			} else {
				enclosing_panel(
					shinybusy::use_busy_spinner(spin = shinybusy_spin, position = shinybusy_position),
					div(reset_message(), style = 'color:red'),
					div(
						textInput(inputId = NS(id, 'reset_password_code'),
								  label = 'Geben Sie den Code aus der E-Mail ein:',
								  value = '')
					),
					# br(),
					actionButton(inputId = NS(id, 'send_reset_password_code'),
								 label = 'Code erneut senden'),
					actionButton(inputId = NS(id, 'submit_reset_password_code'),
								 label = 'Absenden')
				)
			}
		})

		observeEvent(input$submit_reset_password_code, {
			if(input$reset_password_code == reset_code()) {
				reset_code_verify(input$reset_password_code)
			} else {
				reset_message('Code ist nicht korrekt')
			}
		})

		observeEvent(input$reset_new_password, {
			if(input$reset_password1 == input$reset_password2) {
				query <- paste0(
					"UPDATE ", users_table, " SET password = '",
					get_password(input$reset_password1),
					"' WHERE user_id = '", reset_user_id(), "'"
				)
				DBI::dbSendQuery(db_conn, query)
				add_activitiy(reset_user_id(), 'password_reset')
				reset_message('Passwort erfolgreich aktualisiert. Bitte gehen Sie zum Anmelde-Tab.')
				reset_code('')
				reset_code_verify('')
				reset_user_id('')
				reset_email('')
			} else {
				reset_message('Passwörter stimmen nicht überein.')
			}
		})

		observeEvent(input$send_reset_password_code, {
			email_address <- isolate(input$forgot_password_email)

			# Find user by email
			user <- get_user_by_email(email_address)

			if(nrow(user) == 0) {
				reset_message(paste0(email_address, ' not found.'))
			} else {
				code <- generate_code()
				shinybusy::show_spinner()
				tryCatch({
					reset_user_id(user$user_id)
					reset_email(email_address)
					emailer(to_email = email_address,
							subject = reset_password_subject,
							message = sprintf(reset_email_message, code))
					reset_code(code)
				}, error = function(e) {
					reset_message(paste0('Error sending email: ', as.character(e)))
				})
				shinybusy::hide_spinner()
			}
		})

		return(USER)
	})
}
