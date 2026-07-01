package routes

import (
	"github.com/gofiber/fiber/v3"
	"github.com/routerarchitects/mango-parental-control/internal/db"
	"github.com/routerarchitects/mango-parental-control/internal/http/handlers"
	subsysteroutes "github.com/routerarchitects/ow-common-mods/fiber/system-routes"
)

type Deps struct {
	DB          *db.Database
	AuthHandler fiber.Handler
	Subsystem   subsysteroutes.Config
}

// RegisterPublic configures the public HTTP router paths.
func RegisterPublic(app *fiber.App, deps Deps) {
	registerLivenessRoute(app)

	// Create authenticated route group
	group := app.Group("", deps.AuthHandler)

	h := handlers.NewServiceHandler(deps.DB)
	registerAPIRoutes(group, h)
}

// RegisterPrivate configures the private/internal HTTP router paths.
func RegisterPrivate(app *fiber.App, deps Deps) {
	registerLivenessRoute(app)

	// Create authenticated route group
	group := app.Group("", deps.AuthHandler)

	// Register system diagnostics routes
	subsysteroutes.RegisterRoutes(deps.Subsystem, group)

	h := handlers.NewServiceHandler(deps.DB)
	registerAPIRoutes(group, h)
}

func registerAPIRoutes(router fiber.Router, h *handlers.ServiceHandler) {
	// Group routes
	router.Get("/api/v1/subscribers/:subscriber_id/groups", h.ListGroups)
	router.Post("/api/v1/subscribers/:subscriber_id/groups", h.CreateGroup)
	router.Get("/api/v1/subscribers/:subscriber_id/groups/:group_id", h.GetGroup)
	router.Put("/api/v1/subscribers/:subscriber_id/groups/:group_id", h.UpdateGroup)
	router.Delete("/api/v1/subscribers/:subscriber_id/groups/:group_id", h.DeleteGroup)

	// Device routes
	router.Get("/api/v1/subscribers/:subscriber_id/groups/:group_id/devices", h.ListDevices)
	router.Post("/api/v1/subscribers/:subscriber_id/groups/:group_id/devices", h.AddDevice)
	router.Get("/api/v1/subscribers/:subscriber_id/groups/:group_id/devices/:client_mac", h.GetDevice)
	router.Delete("/api/v1/subscribers/:subscriber_id/groups/:group_id/devices/:client_mac", h.RemoveDevice)

	// Schedule routes
	router.Get("/api/v1/subscribers/:subscriber_id/schedules", h.ListSchedules)
	router.Post("/api/v1/subscribers/:subscriber_id/schedules", h.CreateSchedule)
	router.Get("/api/v1/subscribers/:subscriber_id/schedules/:schedule_id", h.GetSchedule)
	router.Put("/api/v1/subscribers/:subscriber_id/schedules/:schedule_id", h.UpdateSchedule)
	router.Delete("/api/v1/subscribers/:subscriber_id/schedules/:schedule_id", h.DeleteSchedule)

	// Group-Schedule links
	router.Get("/api/v1/subscribers/:subscriber_id/groups/:group_id/schedules", h.ListLinkedSchedules)
	router.Get("/api/v1/subscribers/:subscriber_id/groups/:group_id/schedules/:schedule_id", h.GetGroupScheduleLink)
	router.Post("/api/v1/subscribers/:subscriber_id/groups/:group_id/schedules", h.LinkSchedule)
	router.Put("/api/v1/subscribers/:subscriber_id/groups/:group_id/schedules", h.ReplaceSchedules)
	router.Delete("/api/v1/subscribers/:subscriber_id/groups/:group_id/schedules/:schedule_id", h.UnlinkSchedule)
}

func registerLivenessRoute(app *fiber.App) {
	app.Get("/livez", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
}
