%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% @author Mark  Mzyk <mm@chef.io>
%% Copyright 2015 Chef Software, Inc.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%


-module(oc_chef_authz_acl_constraints).

-export([check_acl_constraints/4]).

check_acl_constraints(AuthzId, Type, AclPerm, Ace) ->
  case lists:filtermap(fun(Check) -> apply_check(Check, AuthzId, Type, AclPerm, Ace) end, acl_checks()) of
    [] ->
      ok;
    Failures ->
      Failures
  end.

acl_checks() ->
  [
    fun check_admin_group_removal_from_grant_ace/4
  ].

apply_check(Check, AuthzId, Type, AclPerm, Ace) ->
  Check(AuthzId, Type, AclPerm, Ace).

check_admin_group_removal_from_grant_ace(AuthzId, Type, AclPerm, NewAce) ->
  %% It is necessary to pull the current ace and compare to the new ace.
  %% This is because there are some groups that don't have the admin
  %% group by default, such as billing-admins. This will have the effect
  %% that if a group doesn't have the admin group, but then it is later added,
  %% the admin group will never be able to be removed.
  case AclPerm of
    <<"grant">> ->
      NewGroups = extract_acl_groups(AclPerm, NewAce),
      CurrentAce = oc_chef_authz_acl:fetch(Type, AuthzId),
      CurrentGroups = extract_acl_groups(AclPerm, CurrentAce),
      case check_admin_group_removal(CurrentGroups, NewGroups) of
        not_removed ->
          false;
        removed ->
          {true, attempted_admin_group_removal_grant_ace}
      end;
    _Other ->
      ok
  end.

check_admin_group_removal(CurrentGroups, NewGroups) ->
  %% Check if the CurrentGroups contains the admin group. If it doesn't, there
  %% is nothing to do. If it does, then check if the admin group is present in
  %% the new group.
  case contains_admin_group(CurrentGroups) of
    false ->
      not_removed;
    true ->
      case contains_admin_group(NewGroups) of
        true ->
          not_removed;
        false ->
          removed
      end
  end.

contains_admin_group(Groups) ->
  case lists:filter(fun(X) -> X =:= <<"admins">> end, Groups) of
    [] ->
        false;
    _NonEmpty ->
        true
    end.

extract_acl_groups(AclPerm, Ace) ->
      ActorsAndGroups = ej:get({AclPerm}, Ace),
      ej:get({<<"groups">>}, ActorsAndGroups).


