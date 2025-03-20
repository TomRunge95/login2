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
		# Hash function for email/username
		hash_email <- function(email) {
			email |>
				tolower() |>
				charToRaw() |>
				sodium::sha256() |>
				sodium::bin2hex()
		}

		# Create a lookup table to store email-to-hashed email mapping during session
		email_mapping <- reactiveVal(list())

		# Check to see if the users_table is already in the database, if not
		# create the table.
		if(!users_table %in% DBI::dbListTables(db_conn)) {
			users <- data.frame(username = character(),  # This will store hashed emails
								email_sent_to = character(), # This will store the original email only during registration
								password = character(),
								created_date = numeric(),
								stringsAsFactors = FALSE)
			if(!is.null(additional_fields)) {
				for(i in seq_len(length(additional_fields))) {
					users[,names(additional_fields[i])] <- character()
				}
			}
			DBI::dbWriteTable(db_conn, users_table, users)
		} else {
			# Check if email_sent_to column exists, add if not
			users_columns <- names(DBI::dbReadTable(db_conn, users_table))
			if(!"email_sent_to" %in% users_columns) {
				DBI::dbSendQuery(db_conn,
								 paste0("ALTER TABLE ", users_table, " ADD COLUMN email_sent_to TEXT"))
			}
		}

		if(!activity_table %in% DBI::dbListTables(db_conn)) {
			activity <- data.frame(username = character(),  # This will store hashed emails
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

		get_user <- function(username_hash) {
			user <- DBI::dbSendQuery(
				db_conn,
				paste0("SELECT * FROM ", users_table, " WHERE username='", username_hash, "'")
			) |> DBI::dbFetch()
			return(user)
		}

		add_user <- function(newuser) {
			DBI::dbWriteTable(db_conn, users_table, newuser, append = TRUE)
		}

		generate_code <- function() {
			sample(10 ^ code_length - 1, size = 1) |>
				as.character() |>
				stringr::str_pad(width = code_length, pad = '0')
		}

		USER <- reactiveValues()
		USER$logged_in <- FALSE
		USER$unique <- format(Sys.time(), '%Y%m%d%H%M%S')
		USER$username <- NA
		USER$email <- NA  # Store the actual email for application use
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
					cookie_value <- decrypt_cookie(cookie_value)
				}

				# The cookie_value is now the hashed email
				user <- get_user(cookie_value)
				if(nrow(user) > 0) {
					USER$username <- cookie_value  # Store the hash
					USER$email <- user$email_sent_to  # Store the email if available
					USER$logged_in <- TRUE
					for(i in names(additional_fields)) {
						USER[[i]] <- user[1,i]
					}
					add_activitiy(cookie_value, 'login_cookie')
				}
			}, error = function(e) {
				warning(paste0('Error retrieving cookie value.'))
				cookies::remove_cookie(cookie_name = cookie_name)
			})
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
			users <- get_users()
			email <- input$username
			email_hash <- hash_email(email)
			password <- get_password(input$password)

			# Find user by the hash, not the email itself
			Id.username <- which(users$username == email_hash)

			if(length(Id.username) != 1) {
				login_message('Username nicht gefunden.')
			} else if(password != users[Id.username,]$password) {
				login_message('Inkorrektes Passwort')
			} else {
				if(!is.null(input$remember_me)) {
					if(input$remember_me) {
						cookie_value <- email_hash  # Store the hash, not the email
						if(!is.null(cookie_key)) {
							cookie_value <- encrypt_cookie(email_hash)
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

				# Update email mapping for this session
				current_mapping <- email_mapping()
				current_mapping[[email_hash]] <- email
				email_mapping(current_mapping)

				login_message('')
				USER$logged_in <- TRUE
				USER$username <- email_hash  # Store the hash
				USER$email <- email  # Store the actual email for application use
				for(i in names(additional_fields)) {
					USER[[i]] <- users[Id.username, i]
				}
				add_activitiy(email_hash, 'login')
			}
		})

		##### User logout ######################################################
		observeEvent(input$logout, {
			add_activitiy(USER$username, 'logout')
			USER$logged_in <- FALSE
			USER$username <- ''
			USER$email <- ''
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
		new_user_values <- reactiveVal(data.frame())
		new_user_code_verify <- reactiveVal('')
		new_user_email <- reactiveVal('')

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
			users <- get_users()
			email <- input$new_username
			email_hash <- hash_email(email)
			password1 <- get_password(input$new_password1)
			password2 <- get_password(input$new_password2)

			# Check if email hash exists in database
			id.username <- which(users$username == email_hash)

			if(length(id.username) > 0) {
				new_user_message(paste0('Account exisitiert bereits für ', email))
			} else if(password1 != password2) {
				new_user_message('Passwörter stimmen nicht überein.')
			} else if(input$new_password1 == '') {
				new_user_message('Bitte geben Sie ein korrektes Passwort ein.')
			} else {
				# Store both the hash and the original email
				newuser <- data.frame(
					username = email_hash,  # Store hash in username field
					email_sent_to = email,  # Store original email temporarily
					password = password1,
					created_date = Sys.time(),
					stringsAsFactors = FALSE
				)

				if(!is.null(additional_fields)) {
					for(i in seq_len(length(additional_fields))) {
						newuser[1,names(additional_fields)[i]] <- input[[names(additional_fields)[i]]]
					}
				}

				for(i in names(users)[(!names(users) %in% names(newuser))]) {
					newuser[,i] <- NA # Make sure the data.frames line up
				}

				# Save the email for later use in this session
				new_user_email(email)

				if(verify_email) {
					shinybusy::show_spinner()
					new_user_values(newuser)
					code <- generate_code()
					tryCatch({
						emailer(to_email = email,
								subject = new_account_subject,
								message = sprintf(create_account_message, code))
						new_user_code_verify(code)
					}, error = function(e) {
						message(e)
						reset_message(paste0('Error sending email: ', as.character(e)))
					})
					shinybusy::hide_spinner()
				} else {
					add_user(newuser)
					add_activitiy(newuser[1,]$username, 'create_account')
					new_user_message(paste0('Neuer Account wurde erstellt für: ', email,
											'. Sie können sich nun einloggen.'))
				}
			}
		})

		observeEvent(input$submit_new_user_code, {
			if(input$submit_new_user_code == 1) {
				code <- isolate(input$new_user_code)
				if(nchar(code) != 6 | reset_code() != code) {
					new_user_message('Code ist nicht korrekt')
				} else {
					newuser <- new_user_values()

					# Update email mapping for this session
					email <- newuser$email_sent_to
					email_hash <- newuser$username
					current_mapping <- email_mapping()
					current_mapping[[email_hash]] <- email
					email_mapping(current_mapping)

					# Add user to database
					add_user(newuser)
					new_user_values(data.frame())
					new_user_code_verify('')
					new_user_message(paste0('Neuer Account wurde erstellt für: ',
											email,
											'. Sie können sich nun einloggen.'))
					add_activitiy(email_hash, 'create_account')
				}
			}
		})

		observeEvent(input$send_new_user_code, {
			tryCatch({
				shinybusy::show_spinner()
				code <- generate_code()
				newuser <- new_user_values()
				email_address <- newuser[1,]$email_sent_to
				emailer(to_email = email_address,
						subject = new_account_subject,
						message = sprintf(create_account_message, code))
				new_user_code_verify(code)
				new_user_message('Ein neue Code wurde versendet')
				shinybusy::hide_spinner()
			}, error = function(e) {
				message(e)
				reset_message(paste0('Error sending email: ', as.character(e)))
			})
		})


		##### Reset password ###################################################
		reset_code <- reactiveVal('')
		reset_code_verify <- reactiveVal('')
		reset_message <- reactiveVal('')
		reset_username <- reactiveVal('')
		reset_email <- reactiveVal('')

		output$reset_password_ui <- renderUI({
			if(is.null(emailer)) {
				return(div('Email server has not been configured.'))
			}

			code <- isolate(input$reset_password_code)
			reset_password <- FALSE
			if(nchar(reset_code_verify()) == 6) {
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
			if(input$submit_reset_password_code == 1) {
				code <- isolate(input$reset_password_code)
				reset_code_verify(code)
				if(nchar(code) != 6 & reset_code() == code) {
					reset_message('Code ist nicht korrekt')
				}
			}
		})

		observeEvent(input$reset_new_password, {
			if(input$reset_password1 == input$reset_password2) {
				query <- paste0(
					"UPDATE ", users_table, " SET password = '",
					get_password(input$reset_password1),
					"' WHERE username = '", reset_username(), "'"
				)
				DBI::dbSendQuery(db_conn, query)
				add_activitiy(reset_username(), 'password_reset')
				reset_message('Passwort erfolgreich aktualisiert. Bitte gehen Sie zum Anmelde-Tab.')
				reset_code('')
			} else {
				reset_message('Passwörter stimmen nicht überein.')
			}
		})

		observeEvent(input$send_reset_password_code, {
			email_address <- isolate(input$forgot_password_email)
			email_hash <- hash_email(email_address)

			# Get user by hash
			user <- get_user(email_hash)

			if(nrow(user) == 0) {
				reset_message(paste0(email_address, ' nicht gefunden.'))
			} else {
				code <- generate_code()
				shinybusy::show_spinner()
				tryCatch({
					# Check if we have the original email
					if(!is.na(user$email_sent_to) && user$email_sent_to != "") {
						# Use the stored email
						email_to_use <- user$email_sent_to
					} else {
						# Use the provided email
						email_to_use <- email_address
					}

					reset_username(email_hash)
					reset_email(email_to_use)

					emailer(to_email = email_to_use,
							subject = reset_password_subject,
							message = sprintf(reset_email_message, code))
					reset_code(code)
				}, error = function(e) {
					reset_message(paste0('Error sending email: ', as.character(e)))
				})
				shinybusy::hide_spinner()
			}
		})

		# Clean up task: After account is created and verified,
		# you can remove the email from database to only keep the hash
		# This can be scheduled or triggered at a specific time
		clean_emails <- function() {
			tryCatch({
				query <- paste0("UPDATE ", users_table, " SET email_sent_to = NULL WHERE email_sent_to IS NOT NULL")
				DBI::dbSendQuery(db_conn, query)
			}, error = function(e) {
				message(paste0("Error cleaning emails: ", as.character(e)))
			})
		}

		# You could call clean_emails() function after confirmation or at a regular interval

		return(USER)
	})
}

