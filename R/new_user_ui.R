#' UI for creating a new user account.
#'
#' This will render the UI for users to create an account.
#'
#' @param id id unique ID for the Shiny Login module.
#' @return `shiny` object containing the input fields for a user to create an account.
#' @export
new_user_ui <- function(id) {
	is_not_logged_in(
		id = id,
		htmltools::attachDependencies(
			x = div(
				style = 'background-color: #f0f0f0; padding: 20px;', # Optional: Hintergrundfarbe und Padding
				uiOutput(NS(id, 'new_user_ui')) # Dein UI-Output für den neuen Benutzer
			),
			value = use_login(),
			append = TRUE
		)
	)
}
