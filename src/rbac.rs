//! Role-based access control inside an organization.
//!
//! Every permission check of the web UI and API goes through
//! [`Role::allows`], so the role/permission matrix lives in one place.
//! Instance-wide administration (user management, sync) is a separate flag
//! on the account (`is_admin`).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Full control, including members and deletion of the organization
    Owner,
    /// Manages projects, applications, subscriptions, notifications; triages CVEs
    Editor,
    /// Read-only access
    Viewer,
    /// The figures of the Overview and nothing else: no list, no CVE, no name
    /// of an application. Ranks below viewer.
    Executive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Read the figures of the Overview (`deadlines::Figures`), and nothing they do not imply
    Summary,
    /// Read projects, watchlists, reports
    View,
    /// Change the treatment status of watchlist entries
    Triage,
    /// Create/delete projects, applications, subscriptions, notifications
    ManageProjects,
    /// Delete a project (its decision history is kept)
    DeleteProject,
    /// Add/remove members and change their role
    ManageMembers,
    /// Delete the organization
    DeleteOrganization,
}

impl Role {
    /// From the highest to the lowest
    pub const ALL: [Role; 4] = [Role::Owner, Role::Editor, Role::Viewer, Role::Executive];

    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "owner" => Some(Role::Owner),
            "editor" => Some(Role::Editor),
            "viewer" => Some(Role::Viewer),
            "executive" => Some(Role::Executive),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Editor => "editor",
            Role::Viewer => "viewer",
            Role::Executive => "executive",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Role::Owner => "full control, members included",
            Role::Editor => "manages projects and triages CVEs",
            Role::Viewer => "read-only",
            Role::Executive => "the figures of the Overview only",
        }
    }

    pub fn allows(self, permission: Permission) -> bool {
        use Permission::*;
        match self {
            Role::Owner => true,
            Role::Editor => matches!(permission, Summary | View | Triage | ManageProjects),
            Role::Viewer => matches!(permission, Summary | View),
            // Reading the project is not implied: every list, page and tool asks for `View`
            Role::Executive => matches!(permission, Summary),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Permission::*;

    #[test]
    fn permission_matrix() {
        let all = [Summary, View, Triage, ManageProjects, DeleteProject, ManageMembers, DeleteOrganization];
        assert!(all.iter().all(|p| Role::Owner.allows(*p)));
        assert_eq!(
            all.map(|p| Role::Editor.allows(p)),
            [true, true, true, true, false, false, false]
        );
        assert_eq!(
            all.map(|p| Role::Viewer.allows(p)),
            [true, true, false, false, false, false, false]
        );
        // The figures, and nothing a viewer has beyond them
        assert_eq!(
            all.map(|p| Role::Executive.allows(p)),
            [true, false, false, false, false, false, false]
        );
    }

    #[test]
    fn roles_roundtrip_and_reject_unknown() {
        for role in Role::ALL {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
        assert_eq!(Role::parse("member"), None);
        assert_eq!(Role::parse("admin"), None);
    }
}
