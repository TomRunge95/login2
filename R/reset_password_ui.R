#' UI for resetting password.
#'
#' Displays UI for users to reset their password. In order for the password
#' reset feature to work credentials to a SMTP server must be passed to the
#' [login::login_server()] function.
#'
#' @param id id unique ID for the Shiny Login module.
#' @return a `shiny` object containing the input fields for a user to reset their password.
#' @export
reset_password_ui <- function(id) {
	dependencies <- cookies::cookie_dependency()
	dependencies[[length(dependencies) + 1]] <- use_login()

	div(style = 'background-color: #f0f0f0; padding: 20px;',
		# Dies sorgt dafür, dass es neu ausgewertet wird, wenn sich der logged_in-Status ändert
		div(textOutput(NS(id, 'logged_in')), style = 'visibility: hidden;'),
		conditionalPanel(
			condition = paste0("output['", NS(id, 'logged_in'), "'] != 'TRUE'"),
			htmltools::attachDependencies(
				x = uiOutput(NS(id, 'reset_password_ui')),
				value = dependencies,
				append = FALSE
			)
		)
	)
}
