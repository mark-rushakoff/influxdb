package middleware_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/influxdata/influxdb/task/backend"

	"github.com/influxdata/influxdb"
	"github.com/influxdata/influxdb/notification/rule"
	"github.com/influxdata/influxdb/task/backend/middleware"
)

func newNotificationRuleSvcStack() (mockedSvc, *middleware.CoordinatingNotificationRuleStore) {
	msvcs := newMockServices()
	return msvcs, middleware.NewNotificationRuleStore(msvcs.notificationSvc, msvcs.taskSvc, msvcs.pipingCoordinator)
}

func TestNotificationRuleCreate(t *testing.T) {
	mocks, nrService := newNotificationRuleSvcStack()
	ch := mocks.pipingCoordinator.taskCreatedChan()

	nr := &rule.HTTP{}
	nr.SetTaskID(4)

	err := nrService.CreateNotificationRule(context.Background(), nr, 1)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case task := <-ch:
		if task.ID != nr.GetTaskID() {
			t.Fatalf("task sent to coordinator doesn't match expected")
		}
	default:
		t.Fatal("didn't receive task")
	}

	mocks.pipingCoordinator.err = fmt.Errorf("bad")
	mocks.notificationSvc.DeleteNotificationRuleF = func(context.Context, influxdb.ID) error { return fmt.Errorf("AARGH") }

	err = nrService.CreateNotificationRule(context.Background(), nr, 1)
	if err.Error() != "schedule task failed: bad\n\tcleanup also failed: AARGH" {
		t.Fatal(err)
	}
}

func TestNotificationRuleUpdateFromInactive(t *testing.T) {
	mocks, nrService := newNotificationRuleSvcStack()
	latest := time.Now().UTC()
	nrService.Now = func() time.Time {
		return latest
	}
	ch := mocks.pipingCoordinator.taskUpdatedChan()

	mocks.notificationSvc.UpdateNotificationRuleF = func(_ context.Context, _ influxdb.ID, c influxdb.NotificationRule, _ influxdb.ID) (influxdb.NotificationRule, error) {
		c.SetTaskID(10)
		c.SetStatus(influxdb.Active)
		c.SetUpdatedAt(latest.Add(-20 * time.Hour))
		return c, nil
	}

	mocks.notificationSvc.PatchNotificationRuleF = func(_ context.Context, id influxdb.ID, _ influxdb.NotificationRuleUpdate) (influxdb.NotificationRule, error) {
		ic := &rule.HTTP{}
		ic.SetTaskID(10)
		ic.SetStatus(influxdb.Active)
		ic.SetUpdatedAt(latest.Add(-20 * time.Hour))
		return ic, nil
	}

	mocks.notificationSvc.FindNotificationRuleByIDF = func(_ context.Context, id influxdb.ID) (influxdb.NotificationRule, error) {
		c := &rule.HTTP{}
		c.SetID(id)
		c.SetTaskID(1)
		c.SetStatus(influxdb.TaskStatusInactive)
		return c, nil
	}

	mocks.taskSvc.FindTaskByIDFn = func(_ context.Context, id influxdb.ID) (*influxdb.Task, error) {
		if id == 1 {
			return &influxdb.Task{ID: id, Status: string(backend.TaskInactive)}, nil
		} else if id == 10 {
			return &influxdb.Task{ID: id, Status: string(backend.TaskActive)}, nil
		}
		return &influxdb.Task{ID: id}, nil
	}

	deadman := &rule.HTTP{}
	deadman.SetTaskID(10)
	deadman.SetStatus(influxdb.Active)

	therule, err := nrService.UpdateNotificationRule(context.Background(), 1, deadman, 11)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case task := <-ch:
		if task.ID != therule.GetTaskID() {
			t.Fatalf("task sent to coordinator doesn't match expected")
		}
		if task.LatestCompleted != latest.Format(time.RFC3339) {
			t.Fatalf("update returned incorrect LatestCompleted, expected %s got %s, or ", latest.Format(time.RFC3339), task.LatestCompleted)
		}
	default:
		t.Fatal("didn't receive task")
	}

	action := influxdb.Active
	therule, err = nrService.PatchNotificationRule(context.Background(), 1, influxdb.NotificationRuleUpdate{Status: &action})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case task := <-ch:
		if task.ID != therule.GetTaskID() {
			t.Fatalf("task sent to coordinator doesn't match expected")
		}
		if task.LatestCompleted != latest.Format(time.RFC3339) {
			t.Fatalf("update returned incorrect LatestCompleted, expected %s got %s, or ", latest.Format(time.RFC3339), task.LatestCompleted)
		}
	default:
		t.Fatal("didn't receive task")
	}

}
func TestNotificationRuleUpdate(t *testing.T) {
	mocks, nrService := newNotificationRuleSvcStack()
	ch := mocks.pipingCoordinator.taskUpdatedChan()

	mocks.notificationSvc.UpdateNotificationRuleF = func(_ context.Context, _ influxdb.ID, c influxdb.NotificationRule, _ influxdb.ID) (influxdb.NotificationRule, error) {
		c.SetTaskID(10)
		return c, nil
	}

	deadman := &rule.HTTP{}
	deadman.SetTaskID(4)

	nr, err := nrService.UpdateNotificationRule(context.Background(), 1, deadman, 2)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case task := <-ch:
		if task.ID != nr.GetTaskID() {
			t.Fatalf("task sent to coordinator doesn't match expected")
		}
	default:
		t.Fatal("didn't receive task")
	}
}

func TestNotificationRulePatch(t *testing.T) {
	mocks, nrService := newNotificationRuleSvcStack()
	ch := mocks.pipingCoordinator.taskUpdatedChan()

	deadman := &rule.HTTP{}
	deadman.SetTaskID(4)

	mocks.notificationSvc.PatchNotificationRuleF = func(context.Context, influxdb.ID, influxdb.NotificationRuleUpdate) (influxdb.NotificationRule, error) {
		return deadman, nil
	}

	nr, err := nrService.PatchNotificationRule(context.Background(), 1, influxdb.NotificationRuleUpdate{})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case task := <-ch:
		if task.ID != nr.GetTaskID() {
			t.Fatalf("task sent to coordinator doesn't match expected")
		}
	default:
		t.Fatal("didn't receive task")
	}
}

func TestNotificationRuleDelete(t *testing.T) {
	mocks, nrService := newNotificationRuleSvcStack()
	ch := mocks.pipingCoordinator.taskDeletedChan()

	mocks.notificationSvc.FindNotificationRuleByIDF = func(_ context.Context, id influxdb.ID) (influxdb.NotificationRule, error) {
		c := &rule.HTTP{}
		c.SetID(id)
		c.SetTaskID(21)
		return c, nil
	}

	err := nrService.DeleteNotificationRule(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case id := <-ch:
		if id != influxdb.ID(21) {
			t.Fatalf("task sent to coordinator doesn't match expected")
		}
	default:
		t.Fatal("didn't receive task")
	}
}
