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

	// Group routes
	group.Get("/api/v1/subscribers/:subscriber_id/groups", h.ListGroups)
	group.Post("/api/v1/subscribers/:subscriber_id/groups", h.CreateGroup)
	group.Get("/api/v1/subscribers/:subscriber_id/groups/:group_id", h.GetGroup)
	group.Put("/api/v1/subscribers/:subscriber_id/groups/:group_id", h.UpdateGroup)
	group.Delete("/api/v1/subscribers/:subscriber_id/groups/:group_id", h.DeleteGroup)

	// Device routes
	group.Get("/api/v1/subscribers/:subscriber_id/groups/:group_id/devices", h.ListDevices)
	group.Post("/api/v1/subscribers/:subscriber_id/groups/:group_id/devices", h.AddDevice)
	group.Get("/api/v1/subscribers/:subscriber_id/groups/:group_id/devices/:client_mac", h.GetDevice)
	group.Delete("/api/v1/subscribers/:subscriber_id/groups/:group_id/devices/:client_mac", h.RemoveDevice)

	// Schedule routes
	group.Get("/api/v1/subscribers/:subscriber_id/schedules", h.ListSchedules)
	group.Post("/api/v1/subscribers/:subscriber_id/schedules", h.CreateSchedule)
	group.Get("/api/v1/subscribers/:subscriber_id/schedules/:schedule_id", h.GetSchedule)
	group.Put("/api/v1/subscribers/:subscriber_id/schedules/:schedule_id", h.UpdateSchedule)
	group.Delete("/api/v1/subscribers/:subscriber_id/schedules/:schedule_id", h.DeleteSchedule)

	// Group-Schedule links
	group.Get("/api/v1/subscribers/:subscriber_id/groups/:group_id/schedules", h.ListLinkedSchedules)
	group.Get("/api/v1/subscribers/:subscriber_id/groups/:group_id/schedules/:schedule_id", h.GetGroupScheduleLink)
	group.Post("/api/v1/subscribers/:subscriber_id/groups/:group_id/schedules", h.LinkSchedule)
	group.Put("/api/v1/subscribers/:subscriber_id/groups/:group_id/schedules", h.ReplaceSchedules)
	group.Delete("/api/v1/subscribers/:subscriber_id/groups/:group_id/schedules/:schedule_id", h.UnlinkSchedule)
}

// RegisterPrivate configures the private/internal HTTP router paths.
func RegisterPrivate(app *fiber.App, deps Deps) {
	registerLivenessRoute(app)

	// Create authenticated route group
	group := app.Group("", deps.AuthHandler)

	// Register system diagnostics routes
	subsysteroutes.RegisterRoutes(deps.Subsystem, group)
}

func registerLivenessRoute(app *fiber.App) {
	app.Get("/livez", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
}
