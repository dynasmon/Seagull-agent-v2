package assessment

import (
	"errors"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/accounts"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

func rule(held assessmentv1.AccountTest_Rule, group ...string) *assessmentv1.AccountTest {
	test := &assessmentv1.AccountTest{Rule: held}
	if len(group) > 0 {
		test.Group = group[0]
	}
	return test
}

func TestAccountsAreJudgedByWhatTheHostsOwnFilesHold(t *testing.T) {
	clean := newHost()
	expect(t, clean, map[string]struct {
		test any
		want answered
	}{
		"only root":          {rule(assessmentv1.AccountTest_RULE_ONLY_ROOT_HAS_USER_ID_0), answered{pass, "no account but root holds user id 0"}},
		"unique uids":        {rule(assessmentv1.AccountTest_RULE_UNIQUE_USER_IDS), answered{pass, "no two hold one user id"}},
		"unique names":       {rule(assessmentv1.AccountTest_RULE_UNIQUE_USER_NAMES), answered{pass, "no two hold one account name"}},
		"unique gids":        {rule(assessmentv1.AccountTest_RULE_UNIQUE_GROUP_IDS), answered{pass, "no two hold one group id"}},
		"unique groups":      {rule(assessmentv1.AccountTest_RULE_UNIQUE_GROUP_NAMES), answered{pass, "no two hold one group name"}},
		"primary groups":     {rule(assessmentv1.AccountTest_RULE_PRIMARY_GROUPS_EXIST), answered{pass, "/etc/group holds the primary group of every account"}},
		"empty shadow":       {rule(assessmentv1.AccountTest_RULE_GROUP_HAS_NO_MEMBERS, "shadow"), answered{pass, "group shadow has no member"}},
		"absent wheel":       {rule(assessmentv1.AccountTest_RULE_GROUP_HAS_NO_MEMBERS, "wheel"), answered{inapplicable, "the host has no group wheel"}},
		"a newer rule":       {rule(assessmentv1.AccountTest_Rule(42)), answered{unsupported, "newer than this agent reads"}},
		"a group for no one": {rule(assessmentv1.AccountTest_RULE_UNIQUE_USER_IDS, "shadow"), answered{unsupported, "it names a group for a rule about no group"}},
	})

	held := newHost()
	held.database.Accounts = append(held.database.Accounts,
		accounts.Account{Name: "toor"}, accounts.Account{Name: "alice", UID: 1002, GID: 1002}, accounts.Account{Name: "carol", UID: 1001, GID: 42},
		accounts.Account{Name: "dave", UID: 1003, GID: 5005})
	held.database.Groups = append(held.database.Groups, accounts.Group{Name: "shadow", GID: 1000, Members: []string{"bob"}}, accounts.Group{Name: "audit", GID: 42})
	expect(t, held, map[string]struct {
		test any
		want answered
	}{
		"another superuser": {rule(assessmentv1.AccountTest_RULE_ONLY_ROOT_HAS_USER_ID_0), answered{fail, "besides root, user id 0 is held by toor"}},
		"a shared uid":      {rule(assessmentv1.AccountTest_RULE_UNIQUE_USER_IDS), answered{fail, "0 by root, toor"}},
		"a shared name":     {rule(assessmentv1.AccountTest_RULE_UNIQUE_USER_NAMES), answered{fail, "alice by 1000, 1002"}},
		"a shared gid":      {rule(assessmentv1.AccountTest_RULE_UNIQUE_GROUP_IDS), answered{fail, "42 by shadow, audit"}},
		"a shared group":    {rule(assessmentv1.AccountTest_RULE_UNIQUE_GROUP_NAMES), answered{fail, "shadow by 42, 1000"}},
		"an orphan":         {rule(assessmentv1.AccountTest_RULE_PRIMARY_GROUPS_EXIST), answered{fail, "dave (5005)"}},
		"shadow members":    {rule(assessmentv1.AccountTest_RULE_GROUP_HAS_NO_MEMBERS, "shadow"), answered{fail, "group shadow has members carol, bob, alice"}},
	})
}

func TestAccountFilesThatCannotBeReadAreAnErrorForEveryAccountCheck(t *testing.T) {
	host := newHost()
	host.failing["accounts"] = errors.New("permission denied")
	expect(t, host, map[string]struct {
		test any
		want answered
	}{
		"only root":   {rule(assessmentv1.AccountTest_RULE_ONLY_ROOT_HAS_USER_ID_0), answered{erred, "the host's account files cannot be read: permission denied"}},
		"unique uids": {rule(assessmentv1.AccountTest_RULE_UNIQUE_USER_IDS), answered{erred, "permission denied"}},
	})
	if host.reads["accounts"] != 1 {
		t.Fatalf("one round read the account files %d times", host.reads["accounts"])
	}
}
