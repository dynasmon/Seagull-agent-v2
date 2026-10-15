package assessment

import (
	"fmt"
	"maps"
	"slices"
	"strconv"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/accounts"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

func (r *round) account(test *assessmentv1.AccountTest) (assessmentv1.Outcome, string) {
	held, err := r.accounts.get(r.host.Accounts)
	if err != nil {
		return assessmentv1.Outcome_OUTCOME_ERROR, "the host's account files cannot be read: " + told(err)
	}
	switch test.GetRule() {
	case assessmentv1.AccountTest_RULE_ONLY_ROOT_HAS_USER_ID_0:
		var others []string
		for _, account := range held.Accounts {
			if account.UID == 0 && account.Name != "root" {
				others = append(others, account.Name)
			}
		}
		if len(others) > 0 {
			return assessmentv1.Outcome_OUTCOME_FAIL, "besides root, user id 0 is held by " + named(others)
		}
		return assessmentv1.Outcome_OUTCOME_PASS, "no account but root holds user id 0"
	case assessmentv1.AccountTest_RULE_UNIQUE_USER_IDS:
		return distinct("user id", held.Accounts, func(account accounts.Account) (string, string) {
			return strconv.FormatUint(uint64(account.UID), 10), account.Name
		})
	case assessmentv1.AccountTest_RULE_UNIQUE_USER_NAMES:
		return distinct("account name", held.Accounts, func(account accounts.Account) (string, string) {
			return account.Name, strconv.FormatUint(uint64(account.UID), 10)
		})
	case assessmentv1.AccountTest_RULE_UNIQUE_GROUP_IDS:
		return distinct("group id", held.Groups, func(group accounts.Group) (string, string) {
			return strconv.FormatUint(uint64(group.GID), 10), group.Name
		})
	case assessmentv1.AccountTest_RULE_UNIQUE_GROUP_NAMES:
		return distinct("group name", held.Groups, func(group accounts.Group) (string, string) {
			return group.Name, strconv.FormatUint(uint64(group.GID), 10)
		})
	case assessmentv1.AccountTest_RULE_PRIMARY_GROUPS_EXIST:
		known := map[uint32]bool{}
		for _, group := range held.Groups {
			known[group.GID] = true
		}
		var orphans []string
		for _, account := range held.Accounts {
			if !known[account.GID] {
				orphans = append(orphans, fmt.Sprintf("%s (%d)", account.Name, account.GID))
			}
		}
		if len(orphans) > 0 {
			return assessmentv1.Outcome_OUTCOME_FAIL, "/etc/group holds no primary group of " + named(orphans)
		}
		return assessmentv1.Outcome_OUTCOME_PASS, "/etc/group holds the primary group of every account"
	case assessmentv1.AccountTest_RULE_GROUP_HAS_NO_MEMBERS:
		name := test.GetGroup()
		var members []string
		found := false
		for _, group := range held.Groups {
			if group.Name != name {
				continue
			}
			found = true
			members = append(members, group.Members...)
			for _, account := range held.Accounts {
				if account.GID == group.GID && !slices.Contains(members, account.Name) {
					members = append(members, account.Name)
				}
			}
		}
		switch {
		case !found:
			return assessmentv1.Outcome_OUTCOME_NOT_APPLICABLE, "the host has no group " + secrets.Bounded(name)
		case len(members) > 0:
			return assessmentv1.Outcome_OUTCOME_FAIL, fmt.Sprintf("group %s has members %s", secrets.Bounded(name), named(members))
		}
		return assessmentv1.Outcome_OUTCOME_PASS, fmt.Sprintf("group %s has no member", secrets.Bounded(name))
	}
	return assessmentv1.Outcome_OUTCOME_UNSUPPORTED, "the agent does not know the rule"
}

// distinct fails when two entries share what keys them, naming them by what
// tells them apart.
func distinct[T any](what string, entries []T, keyed func(T) (string, string)) (assessmentv1.Outcome, string) {
	held := map[string][]string{}
	for _, entry := range entries {
		key, other := keyed(entry)
		held[key] = append(held[key], other)
	}
	var shared []string
	for _, key := range slices.Sorted(maps.Keys(held)) {
		if len(held[key]) > 1 {
			shared = append(shared, fmt.Sprintf("%s by %s", secrets.Bounded(key), named(held[key])))
		}
	}
	if len(shared) > 0 {
		return assessmentv1.Outcome_OUTCOME_FAIL, fmt.Sprintf("more than one holds %s %s", what, named(shared))
	}
	return assessmentv1.Outcome_OUTCOME_PASS, fmt.Sprintf("no two hold one %s", what)
}
