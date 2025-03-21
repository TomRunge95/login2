#' UI for creating a new user account.
#'
#' This will render the UI for users to create an account.
#'
#' @param id id unique ID for the Shiny Login module.
#' @return `shiny` object containing the input fields for a user to create an account.
#' @export
new_user_ui <- function(id) {
	dependencies <- cookies::cookie_dependency()
	dependencies[[length(dependencies) + 1]] <- use_login()

	div(style = 'background-color: #f0f0f0; padding: 20px;',
		# Dies sorgt dafür, dass es neu ausgewertet wird, wenn sich der logged_in-Status ändert
		div(textOutput(NS(id, 'logged_in')), style = 'visibility: hidden;'),
		conditionalPanel(
			condition = paste0("output['", NS(id, 'logged_in'), "'] != 'TRUE'"),
			htmltools::attachDependencies(
				x = uiOutput(NS(id, 'new_user_ui')),
				value = dependencies,
				append = FALSE
			)
		)
	)
}
