#include "stdafx.h"
#include <Crypto/utils.h>
#include <Emu/system_config.h>
#include <Emu/NP/clan_client.h>
#include <wolfssl/wolfcrypt/coding.h>

LOG_CHANNEL(clan_log, "clans");

constexpr const char* jid_format = "%s@un.br.np.playstation.net";

namespace clan
{
	size_t clan_client::curlWriteCallback(void* data, size_t size, size_t nmemb, void* clientp)
	{
		size_t realsize = size * nmemb;
		auto &mem = *static_cast<std::vector<char> *>(clientp);

		size_t offset = mem.size() - 1;
		mem.resize(mem.size() + realsize);
		memcpy(&mem[offset], data, realsize);
		mem[mem.size() - 1] = '\0';

		return realsize;
	}

	SceNpClansError clan_client::createRequest()
	{
		curl = curl_easy_init();
		if (!curl)
		{
			return SceNpClansError::SCE_NP_CLANS_ERROR_NOT_INITIALIZED;
		}

		// Tell curl to use the native CA store for certificate verification
		curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);

		std::string dns_server = g_cfg.net.clans_dns;
		if (dns_server.empty())
		{
			dns_server = g_cfg.net.dns;
		}

		// Check if the address is valid
		bool dns_ok = true;
		if (!dns_server.empty())
		{
			std::string dns_no_port = dns_server.substr(0, dns_server.find(':'));
			if (dns_no_port.empty())
			{
				clan_log.error("Provided Clans DNS server does not have an IP address: '%s'", dns_server);
				dns_ok = false;
			}

			in_addr_t conv;
			if (!inet_pton(AF_INET, dns_no_port.c_str(), &conv))
			{
				clan_log.error("Provided Clans DNS server IP is not valid: '%s'", dns_server);
				dns_ok = false;
			}
		}

		if (dns_ok)
		{
			// Add entries to CURLOPT_RESOLVE for the two domains used for Clans
			curl_slist *servers;
			servers = curl_slist_append(nullptr, std::format("clans-view01.ww.np.community.playstation.net:443:{}", dns_server).c_str());
			servers = curl_slist_append(servers, std::format("clans-rec01.ww.np.community.playstation.net:443:{}", dns_server).c_str());

			curl_easy_setopt(curl, CURLOPT_RESOLVE, servers);
		}

		return SceNpClansError::SCE_NP_CLANS_SUCCESS;
	}

	SceNpClansError clan_client::destroyRequest()
	{
		curl_easy_cleanup(curl);

		return SceNpClansError::SCE_NP_CLANS_SUCCESS;
	}

	SceNpClansError clan_client::sendRequest(std::string endpoint, ClanManagerType type, pugi::xml_document* xmlBody, pugi::xml_document* outResponse)
	{
		bool secure = false;
		pugi::xml_node clan = xmlBody->child("clan");
		if (clan && clan.child("ticket"))
		{
			secure = true;
		}

		std::string typeStr = type == ClanManagerType::VIEW ? "clan_manager_view" : "clan_manager_update";
        std::string secureStr = secure ? "sec" : "func";

		std::string host = type == ClanManagerType::VIEW ? "clans-view01.ww.np.community.playstation.net" : "clans-rec01.ww.np.community.playstation.net";
		std::string url = std::format("https://{}/{}/{}/{}", host, typeStr, secureStr, endpoint);
		// clan_log.todo("Clans Request URL: %s", url);

		std::ostringstream oss;
		xmlBody->save(oss, "\t", 8U);

		std::string xml = oss.str();
		// clan_log.todo("Clans XML Body: %s", xml);

		// CURL Error message buffer
		char err_buf[CURL_ERROR_SIZE];
		err_buf[0] = '\0';

		// static buffer for responses
		static std::vector<char> response;
		response.resize(0);

		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
		curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, err_buf);

		// Add POST data
		curl_easy_setopt(curl, CURLOPT_POST, 1);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, xml.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, xml.size());

		res = curl_easy_perform(curl);

		if (res != CURLE_OK)
		{
			outResponse = nullptr;
			clan_log.error("curl_easy_perform() failed: %s", curl_easy_strerror(res));
			clan_log.error("Error buffer: %s", err_buf);
			return SCE_NP_CLANS_ERROR_BAD_REQUEST;
		}

		// Print the response
		// clan_log.todo("Clans API Response: %s", mem.response);

		// Parse the response
		pugi::xml_parse_result res = outResponse->load_string(response.data());

		if (!res)
		{
			clan_log.error("XML parsing failed: %s", res.description());
			return SCE_NP_CLANS_ERROR_BAD_RESPONSE;
		}

		// Parse the result
		pugi::xml_node clanResult = outResponse->child("clan");
		if (!clanResult)
			return SCE_NP_CLANS_ERROR_BAD_RESPONSE;

		// Parse the 'result' attribute
		pugi::xml_attribute result = clanResult.attribute("result");
		if (!result)
			return SCE_NP_CLANS_ERROR_BAD_RESPONSE;

		std::string result_str = result.as_string();
		if (result_str != "00")
			return static_cast<SceNpClansError>(0x80022800 | std::stoul(result_str, nullptr, 16));

		return SCE_NP_CLANS_SUCCESS;
	}

	std::string clan_client::getClanTicket(np::np_handler& nph)
    {
		// If there's already a ticket, return it
		if (nph.get_ticket().size() > 0) {
			byte* ticket_bytes = new byte[1024];
			uint32_t ticket_size = UINT32_MAX;

			Base64_Encode_NoNl(nph.get_ticket().data(), nph.get_ticket().size(), ticket_bytes, &ticket_size);
			return std::string(reinterpret_cast<char*>(ticket_bytes), ticket_size);
		}

        const auto& npid = nph.get_npid();
		// TODO: DEBUG! Knight needs to fucking whitelist `IV0001-NPXS01001_00`, so for now we're stuck with Home's ID.
        const char* service_id = "EP9000-NPEA00013_00";
        const unsigned char* cookie = nullptr;
        const u32 cookie_size = 0;
        const char* entitlement_id = "NPWR00432_00";
        const u32 consumed_count = 0;

        nph.req_ticket(0x00020001, &npid, service_id, cookie, cookie_size, entitlement_id, consumed_count);

        np::ticket ticket;
        while (ticket.empty()) ticket = nph.get_ticket();

        // Encode the ticket into a base64 string
        byte* ticket_bytes = new byte[1024];
        uint32_t ticket_size = UINT32_MAX;

        Base64_Encode_NoNl(ticket.data(), ticket.size(), ticket_bytes, &ticket_size);

        // Make a string with the base64 ticket
        std::string ticket_str = std::string(reinterpret_cast<char*>(ticket_bytes), ticket_size);

        return ticket_str;
    }

#pragma region Outgoing API Requests
	SceNpClansError clan_client::getClanList(np::np_handler& nph, SceNpClansPagingRequest* paging, SceNpClansEntry* clanList, SceNpClansPagingResult* pageResult)
	{
		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");

        std::string ticket = getClanTicket(nph);
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("start").text().set(paging->startPos);
		clan.append_child("max").text().set(paging->max);

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		SceNpClansError clanRes = sendRequest("get_clan_list", ClanManagerType::VIEW, &doc, &response);

		if (clanRes != SCE_NP_CLANS_SUCCESS)
			return clanRes;

		// Parse the paging result
		pugi::xml_node clanResult = response.child("clan");
		pugi::xml_node list = clanResult.child("list");

		// Currently returned results
		pugi::xml_attribute results = list.attribute("results");
		uint32_t results_count = results.as_uint();

		// Total results in the database
		pugi::xml_attribute total = list.attribute("total");
		uint32_t total_count = total.as_uint();

		// Get each `info` node
		int i = 0;
		for (pugi::xml_node info = list.child("info"); info; info = info.next_sibling("info"))
		{
			pugi::xml_attribute id = info.attribute("id");
			uint32_t clanId = id.as_uint();

			pugi::xml_node name = info.child("name");
			std::string name_str = name.text().as_string();

			pugi::xml_node tag = info.child("tag");
			std::string tag_str = tag.text().as_string();

			pugi::xml_node role = info.child("role");
			int32_t role_int = role.text().as_uint();

			pugi::xml_node status = info.child("status");
			uint32_t status_int = status.text().as_uint();

			pugi::xml_node onlinename = info.child("onlinename");
			std::string onlinename_str = onlinename.text().as_string();

            // NOTE: unused
			// pugi::xml_node allowmsg = info.child("allowmsg");
			// uint32_t allowmsg_int = allowmsg.text().as_uint();

			pugi::xml_node members = info.child("members");
			uint32_t members_int = members.text().as_uint();

			// Create a `SceNpClansEntry` object and add it to the array
			SceNpClansEntry entry = SceNpClansEntry{
				.info = SceNpClansClanBasicInfo{
					.clanId = clanId,
					.numMembers = members_int,
					.name = "",
					.tag = "",
					.reserved = {0, 0},
                },
				.role = static_cast<SceNpClansMemberRole>(role_int),
				.status = static_cast<SceNpClansMemberStatus>(status_int)};

			strncpy(entry.info.name, name_str.c_str(), SCE_NP_CLANS_CLAN_NAME_MAX_LENGTH);
			strncpy(entry.info.tag, tag_str.c_str(), SCE_NP_CLANS_CLAN_TAG_MAX_LENGTH);

			clanList[i] = entry;
			i++;
		}

		*pageResult = SceNpClansPagingResult{
			.count = results_count,
			.total = total_count};

		return SCE_NP_CLANS_SUCCESS;
	}

	SceNpClansError clan_client::getClanInfo(SceNpClanId clanId, SceNpClansClanInfo* clanInfo)
	{
		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("id").text().set(clanId);

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		SceNpClansError clanRes = sendRequest("get_clan_info", ClanManagerType::VIEW, &doc, &response);

		if (clanRes != SCE_NP_CLANS_SUCCESS)
			return clanRes;

		// Parse the paging result
		pugi::xml_node clanResult = response.child("clan");
		pugi::xml_node info = clanResult.child("info");

		std::string name_str = info.child("name").text().as_string();
		std::string tag_str = info.child("tag").text().as_string();
		uint32_t members_int = info.child("members").text().as_uint();
		std::string date_created_str = info.child("date-created").text().as_string();
		std::string description_str = info.child("description").text().as_string();

		// Create a `SceNpClansClanInfo` object
		*clanInfo = SceNpClansClanInfo{
			.info = SceNpClansClanBasicInfo{
				.clanId = clanId,
				.numMembers = members_int,
				.name = "",
				.tag = "",
			},
			.updatable = SceNpClansUpdatableClanInfo{
				.description = "",
			}};

		std::strncpy(clanInfo->info.name, name_str.c_str(), SCE_NP_CLANS_CLAN_NAME_MAX_LENGTH);
		std::strncpy(clanInfo->info.tag, tag_str.c_str(), SCE_NP_CLANS_CLAN_TAG_MAX_LENGTH);
		std::strncpy(clanInfo->updatable.description, description_str.c_str(), SCE_NP_CLANS_CLAN_DESCRIPTION_MAX_LENGTH);

		return SCE_NP_CLANS_SUCCESS;
	}

	SceNpClansError clan_client::getMemberInfo(np::np_handler& nph, SceNpClanId clanId, SceNpId npId, SceNpClansMemberEntry* memInfo)
	{
		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);

        std::string jid_str = std::format(jid_format, npId.handle.data);
        clan.append_child("jid").text().set(jid_str.c_str());

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		SceNpClansError clanRes = sendRequest("get_member_info", ClanManagerType::VIEW, &doc, &response);

		if (clanRes != SCE_NP_CLANS_SUCCESS)
			return clanRes;

		// Parse the paging result
		pugi::xml_node clanResult = response.child("clan");
		pugi::xml_node info = clanResult.child("info");

		pugi::xml_attribute jid = info.attribute("jid");
		std::string npid_str = jid.as_string();

		char username[16 + 1] = {0};

		// Split `jid` at the `@` and get the first part
		sscanf(npid_str.c_str(), "%[^@]", username);

		SceNpId npid;

		// Compare if the username is the same as the RPCN username
		if (!strcmp(username, nph.get_npid().handle.data))
		{
			npid = nph.get_npid();
		}
		else
		{
			npid = SceNpId {};
			std::strncpy(npid.handle.data, username, 16 + 1);
		}

		pugi::xml_node role = info.child("role");
		uint32_t role_int = role.text().as_uint();

		pugi::xml_node status = info.child("status");
		uint32_t status_int = status.text().as_uint();

		pugi::xml_node description = info.child("description");
		std::string description_str = description.text().as_string();

		char description_char[256] = {0};
		strcpy(description_char, description_str.c_str());

		// Create a `SceNpClansMemberEntry` object
		*memInfo = SceNpClansMemberEntry
		{
			.npid = npid,
			.role = static_cast<SceNpClansMemberRole>(role_int),
			.status = static_cast<SceNpClansMemberStatus>(status_int),
			.updatable = SceNpClansUpdatableMemberInfo{
				.description = "",
			}
		};

		std::strncpy(memInfo->npid.handle.data, username, 16 + 1);
		std::strncpy(memInfo->updatable.description, description_char, SCE_NP_CLANS_MEMBER_DESCRIPTION_MAX_LENGTH);

		return SCE_NP_CLANS_SUCCESS;
	}

	SceNpClansError clan_client::getMemberList(np::np_handler& nph, SceNpClanId clanId, SceNpClansPagingRequest* paging, SceNpClansMemberStatus status, SceNpClansMemberEntry* memList, SceNpClansPagingResult* pageResult)
	{
		std::string ticket = getClanTicket(nph);

        pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);
		clan.append_child("start").text().set(paging->startPos);
        clan.append_child("max").text().set(paging->max);

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		SceNpClansError clanRes = sendRequest("get_member_list", ClanManagerType::VIEW, &doc, &response);

		if (clanRes != SCE_NP_CLANS_SUCCESS)
			return clanRes;

        // Parse the paging result
		pugi::xml_node clanResult = response.child("clan");
        pugi::xml_node list = clanResult.child("list");

        // Currently returned results
        pugi::xml_attribute results = list.attribute("results");
        uint32_t results_count = results.as_uint();

        // Total results in the database
        pugi::xml_attribute total = list.attribute("total");
        uint32_t total_count = total.as_uint();

        // Get each `info` node
        int i = 0;
        for (pugi::xml_node info = list.child("info"); info; info = info.next_sibling("info"))
        {
            std::string npid_str = info.attribute("jid").as_string();

			char username[16 + 1] = {0};

			// Split `jid` at the `@` and get the first part
			sscanf(npid_str.c_str(), "%[^@]", username);

			SceNpId npid;

			// Compare if the username is the same as the RPCN username
			if (!strcmp(username, nph.get_npid().handle.data))
			{
				npid = nph.get_npid();
			}
			else
			{
				npid = SceNpId {};
				std::strncpy(npid.handle.data, username, 16 + 1);
			}

            uint32_t role_int = info.child("role").text().as_uint();
            uint32_t status_int = info.child("status").text().as_uint();
            std::string description_str = info.child("description").text().as_string();

            char description_char[256] = {0};
            strcpy(description_char, description_str.c_str());

            // Create a `SceNpClansMemberEntry` object and add it to the array
            SceNpClansMemberEntry entry = SceNpClansMemberEntry
            {
                .npid = npid,
                .role = static_cast<SceNpClansMemberRole>(role_int),
                .status = static_cast<SceNpClansMemberStatus>(status_int),
            };

			std::strncpy(entry.updatable.description, description_char, SCE_NP_CLANS_MEMBER_DESCRIPTION_MAX_LENGTH);

			memList[i] = entry;
            i++;
        }

		*pageResult = SceNpClansPagingResult
        {
			.count = results_count,
			.total = total_count
        };

		return SCE_NP_CLANS_SUCCESS;
	}

    SceNpClansError clan_client::getBlacklist(np::np_handler& nph, SceNpClanId clanId, SceNpClansPagingRequest* paging, SceNpClansBlacklistEntry* bl, SceNpClansPagingResult* pageResult)
    {
        std::string ticket = getClanTicket(nph);

        pugi::xml_document doc = pugi::xml_document();
        pugi::xml_node clan = doc.append_child("clan");
        clan.append_child("ticket").text().set(ticket.c_str());
        clan.append_child("id").text().set(clanId);
        clan.append_child("start").text().set(paging->startPos);
        clan.append_child("max").text().set(paging->max);

        // Send request to server
        pugi::xml_document response = pugi::xml_document();
        SceNpClansError clanRes = sendRequest("get_blacklist", ClanManagerType::VIEW, &doc, &response);

        if (clanRes != SCE_NP_CLANS_SUCCESS)
            return clanRes;

        // Parse the paging result
		pugi::xml_node clanResult = response.child("clan");
        pugi::xml_node list = clanResult.child("list");

        // Currently returned results
        pugi::xml_attribute results = list.attribute("results");
        uint32_t results_count = results.as_uint();

        // Total results in the database
        pugi::xml_attribute total = list.attribute("total");
        uint32_t total_count = total.as_uint();

        // Get each `entry` node
        int i = 0;
        for (pugi::xml_node node = list.child("entry"); node; node = node.next_sibling("entry"))
        {
            pugi::xml_node id = node.child("jid");
            std::string npid_str = id.text().as_string();

            char username[16 + 1] = {0};

            // Split `jid` at the `@` and get the first part
            sscanf(npid_str.c_str(), "%[^@]", username);

            SceNpId npid = SceNpId
            {
                .handle = SceNpOnlineId
                {
                    .data = ""
                }
            };

			std::strncpy(npid.handle.data, username, 17);

			// NOTE: never even returned? Possibly an artefact?

            // pugi::xml_node reason = node.child("reason");
            // std::string reason_str = reason.text().as_string();

            // Create a `SceNpClansBlacklistEntry` object and add it to the array
            SceNpClansBlacklistEntry entry = SceNpClansBlacklistEntry
            {
                .entry = npid,
            };

            bl[i] = entry;
            i++;
        }

        *pageResult = SceNpClansPagingResult
        {
            .count = results_count,
            .total = total_count
        };

        return SCE_NP_CLANS_SUCCESS;
    }

	SceNpClansError clan_client::addBlacklistEntry(np::np_handler& nph, SceNpClanId clanId, SceNpId npId)
	{
		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);

		std::string jid_str = std::format(jid_format, npId.handle.data);
		clan.append_child("jid").text().set(jid_str.c_str());

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		return sendRequest("record_blacklist_entry", ClanManagerType::UPDATE, &doc, &response);
	}

	SceNpClansError clan_client::removeBlacklistEntry(np::np_handler& nph, SceNpClanId clanId, SceNpId npId)
	{
		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);

        std::string jid_str = std::format(jid_format, npId.handle.data);
        clan.append_child("jid").text().set(jid_str.c_str());

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		return sendRequest("delete_blacklist_entry", ClanManagerType::UPDATE, &doc, &response);
	}

	SceNpClansError clan_client::clanSearch(SceNpClansPagingRequest* paging, SceNpClansSearchableName* search, SceNpClansClanBasicInfo* clanList, SceNpClansPagingResult* pageResult)
	{
		pugi::xml_document doc = pugi::xml_document();
        pugi::xml_node clan = doc.append_child("clan");
        clan.append_child("start").text().set(paging->startPos);
        clan.append_child("max").text().set(paging->max);

		pugi::xml_node filter = clan.append_child("filter");
		pugi::xml_node name = filter.append_child("name");

		static const char *searchOpNames[] = { "eq", "ne", "gt", "ge", "lt", "le", "lk" };

		name.append_attribute("op").set_value(searchOpNames[search->nameSearchOp]);
		name.append_attribute("value").set_value(search->name);

        // Send request to server
        pugi::xml_document response = pugi::xml_document();
        SceNpClansError clanRes = sendRequest("clan_search", ClanManagerType::VIEW, &doc, &response);

        if (clanRes != SCE_NP_CLANS_SUCCESS)
            return clanRes;

        // Parse the paging result
		pugi::xml_node clanResult = response.child("clan");
        pugi::xml_node list = clanResult.child("list");

        // Currently returned results
        pugi::xml_attribute results = list.attribute("results");
        uint32_t results_count = results.as_uint();

        // Total results in the database
        pugi::xml_attribute total = list.attribute("total");
        uint32_t total_count = total.as_uint();

        // Get each `info` node
        int i = 0;
        for (pugi::xml_node node = list.child("info"); node; node = node.next_sibling("info"))
        {
            uint32_t clanId = node.attribute("id").as_uint();
            std::string name_str = node.child("name").text().as_string();
			std::string tag_str = node.child("tag").text().as_string();
			uint32_t members_int = node.child("members").text().as_uint();

            // Create a `SceNpClansClanBasicInfo` object and add it to the array
			SceNpClansClanBasicInfo entry = SceNpClansClanBasicInfo
			{
				.clanId = clanId,
				.numMembers = members_int,
				.name = "",
				.tag = "",
				.reserved = {0, 0},
			};

			strncpy(entry.name, name_str.c_str(), name_str.size());
			strncpy(entry.tag, tag_str.c_str(), tag_str.size());

            clanList[i] = entry;
            i++;
        }

        *pageResult = SceNpClansPagingResult
        {
            .count = results_count,
            .total = total_count
        };

        return SCE_NP_CLANS_SUCCESS;
	}

	SceNpClansError clan_client::requestMembership(np::np_handler& nph, SceNpClanId clanId, SceNpClansMessage* message)
	{
		// Server doesn't implement this yet
		UNUSED(message);

		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		return sendRequest("request_membership", ClanManagerType::UPDATE, &doc, &response);
	}

	SceNpClansError clan_client::cancelRequestMembership(np::np_handler& nph, SceNpClanId clanId)
	{
		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		return sendRequest("cancel_request_membership", ClanManagerType::UPDATE, &doc, &response);
	}

	SceNpClansError clan_client::sendMembershipResponse(np::np_handler& nph, SceNpClanId clanId, SceNpId npId, SceNpClansMessage* message, b8 allow)
	{
		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);

        std::string jid_str = std::format(jid_format, npId.handle.data);
        clan.append_child("jid").text().set(jid_str.c_str());

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		return sendRequest(allow ? "accept_membership_request" : "decline_membership_request", ClanManagerType::UPDATE, &doc, &response);
	}

	SceNpClansError clan_client::sendInvitation(np::np_handler& nph, SceNpClanId clanId, SceNpId npId, SceNpClansMessage* message)
	{
		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);

        std::string jid_str = std::format(jid_format, npId.handle.data);
        clan.append_child("jid").text().set(jid_str.c_str());

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		return sendRequest("send_invitation", ClanManagerType::UPDATE, &doc, &response);
	}

	SceNpClansError clan_client::cancelInvitation(np::np_handler& nph, SceNpClanId clanId, SceNpId npId)
	{
		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);

        std::string jid_str = std::format(jid_format, npId.handle.data);
        clan.append_child("jid").text().set(jid_str.c_str());

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		return sendRequest("cancel_invitation", ClanManagerType::UPDATE, &doc, &response);
	}

	SceNpClansError clan_client::sendInvitationResponse(np::np_handler& nph, SceNpClanId clanId, SceNpClansMessage* message, b8 accept)
	{
		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		return sendRequest(accept ? "accept_invitation" : "decline_invitation", ClanManagerType::UPDATE, &doc, &response);
	}

	SceNpClansError clan_client::updateMemberInfo(np::np_handler& nph, SceNpClanId clanId, SceNpClansUpdatableMemberInfo* info)
	{
		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);

		pugi::xml_node role = clan.append_child("onlinename");
		role.text().set(nph.get_npid().handle.data);

		pugi::xml_node description = clan.append_child("description");
		description.text().set(info->description);

		pugi::xml_node status = clan.append_child("bin-attr1");

		byte binAttr1[SCE_NP_CLANS_MEMBER_BINARY_ATTRIBUTE1_MAX_SIZE * 2 + 1] = {0};
		uint32_t binAttr1Size = UINT32_MAX;
		Base64_Encode_NoNl(info->binAttr1, info->binData1Size, binAttr1, &binAttr1Size);

		if (binAttr1Size == UINT32_MAX)
			return SCE_NP_CLANS_ERROR_INVALID_ARGUMENT;

		// if we don't explicitly cast it to a char ptr, chooses first available matching overload
		// in this case, is set(bool)
		// so instead of the base64 data it'd just send a 0x01 byte lol
		status.text().set(reinterpret_cast<char *>(binAttr1));

		pugi::xml_node allowMsg = clan.append_child("allow-msg");
		allowMsg.text().set(static_cast<uint32_t>(info->allowMsg));

		pugi::xml_node size = clan.append_child("size");
		size.text().set(info->binData1Size);

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		return sendRequest("update_member_info", ClanManagerType::UPDATE, &doc, &response);
	}

	SceNpClansError clan_client::updateClanInfo(np::np_handler& nph, SceNpClanId clanId, SceNpClansUpdatableClanInfo* info)
	{
		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);

		// TODO: implement binary and integer attributes (not implemented in server yet)

		pugi::xml_node description = clan.append_child("description");
		description.text().set(info->description);

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		return sendRequest("update_clan_info", ClanManagerType::UPDATE, &doc, &response);
	}

	SceNpClansError clan_client::joinClan(np::np_handler& nph, SceNpClanId clanId)
	{
		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		return sendRequest("join_clan", ClanManagerType::UPDATE, &doc, &response);
	}

	SceNpClansError clan_client::leaveClan(np::np_handler& nph, SceNpClanId clanId)
	{
		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		return sendRequest("leave_clan", ClanManagerType::UPDATE, &doc, &response);
	}

	SceNpClansError clan_client::kickMember(np::np_handler& nph, SceNpClanId clanId, SceNpId npId, SceNpClansMessage* message)
	{
		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);

        std::string jid_str = std::format(jid_format, npId.handle.data);
        clan.append_child("jid").text().set(jid_str.c_str());

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		return sendRequest("kick_member", ClanManagerType::UPDATE, &doc, &response);
	}

	SceNpClansError clan_client::changeMemberRole(np::np_handler& nph, SceNpClanId clanId, SceNpId npId, SceNpClansMemberRole role)
	{
		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);

        std::string jid_str = std::format(jid_format, npId.handle.data);
        clan.append_child("jid").text().set(jid_str.c_str());

		pugi::xml_node roleNode = clan.append_child("role");
		roleNode.text().set(static_cast<uint32_t>(role));

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		return sendRequest("change_member_role", ClanManagerType::UPDATE, &doc, &response);
	}

	SceNpClansError clan_client::retrieveAnnouncements(np::np_handler& nph, SceNpClanId clanId, SceNpClansPagingRequest* paging, SceNpClansMessageEntry* announcements, SceNpClansPagingResult* pageResult)
	{
		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);
		clan.append_child("start").text().set(paging->startPos);
		clan.append_child("max").text().set(paging->max);

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		SceNpClansError clanRes = sendRequest("retrieve_announcements", ClanManagerType::VIEW, &doc, &response);

		if (clanRes != SCE_NP_CLANS_SUCCESS)
			return clanRes;

		// Parse the paging result
		pugi::xml_node clanResult = response.child("clan");
		pugi::xml_node list = clanResult.child("list");

		// Currently returned results
		pugi::xml_attribute results = list.attribute("results");
		uint32_t results_count = results.as_uint();

		// Total results in the database
		pugi::xml_attribute total = list.attribute("total");
		uint32_t total_count = total.as_uint();

		// Get each `msg-info` node
		int i = 0;
		for (pugi::xml_node node = list.child("msg-info"); node; node = node.next_sibling("msg-info"))
		{
			pugi::xml_attribute id = node.attribute("id");
			uint32_t msgId = id.as_uint();

			std::string subject_str = node.child("subject").text().as_string();
			std::string msg_str = node.child("msg").text().as_string();
			std::string npid_str = node.child("jid").text().as_string();
			std::string msg_date = node.child("msg-date").text().as_string();

			char username[16 + 1] = {0};

			// Split `jid` at the `@` and get the first part
			sscanf(npid_str.c_str(), "%[^@]", username);

			// clan_log.todo("sceNpId npid_str: %s", npid_str);
			// clan_log.todo("sceNpId username: %s", username);

			SceNpId npid;

			// Compare if the username is the same as the RPCN username
			if (!strcmp(username, nph.get_npid().handle.data))
			{
				npid = nph.get_npid();
			}
			else
			{
				npid = SceNpId {};
				std::strncpy(npid.handle.data, username, 16 + 1);
			}

			// TODO: implement `binData` and `fromId`

			// Create a `SceNpClansMessageEntry` object and add it to the array
			SceNpClansMessageEntry entry = SceNpClansMessageEntry
			{
				.mId = msgId,
				.message = SceNpClansMessage {
					.subject = "",
					.body = "",
				},
				.npid = npid,
				.postedBy = clanId,
			};

			// clan_log.todo("sceNpId: %s", npid.handle.data);

			strncpy(entry.message.subject, subject_str.c_str(), subject_str.size());
			strncpy(entry.message.body, msg_str.c_str(), msg_str.size());

			announcements[i] = entry;
			i++;
		}

		*pageResult = SceNpClansPagingResult
		{
			.count = results_count,
			.total = total_count
		};

		return SCE_NP_CLANS_SUCCESS;
	}

	SceNpClansError clan_client::postAnnouncement(np::np_handler& nph, SceNpClanId clanId, SceNpClansMessage* announcement, SceNpClansMessageData* data, u32 duration, SceNpClansMessageId* msgId)
	{
		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);

		pugi::xml_node subject = clan.append_child("subject");
		subject.text().set(announcement->subject);

		pugi::xml_node msg = clan.append_child("msg");
		msg.text().set(announcement->body);

		pugi::xml_node expireDate = clan.append_child("expire-date");
		expireDate.text().set(duration);

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		SceNpClansError clanRes = sendRequest("post_announcement", ClanManagerType::UPDATE, &doc, &response);

		if (clanRes != SCE_NP_CLANS_SUCCESS)
			return clanRes;

		// Get the message ID
		pugi::xml_node clanResult = response.child("clan");
		pugi::xml_node msgIdNode = clanResult.child("id");
		*msgId = msgIdNode.text().as_uint();

		return SCE_NP_CLANS_SUCCESS;
	}

	SceNpClansError clan_client::deleteAnnouncement(np::np_handler& nph, SceNpClanId clanId, SceNpClansMessageId announcementId)
	{
		std::string ticket = getClanTicket(nph);

		pugi::xml_document doc = pugi::xml_document();
		pugi::xml_node clan = doc.append_child("clan");
		clan.append_child("ticket").text().set(ticket.c_str());
		clan.append_child("id").text().set(clanId);
		clan.append_child("msg-id").text().set(announcementId);

		// Send request to server
		pugi::xml_document response = pugi::xml_document();
		return sendRequest("delete_announcement", ClanManagerType::UPDATE, &doc, &response);
	}
}
#pragma endregion