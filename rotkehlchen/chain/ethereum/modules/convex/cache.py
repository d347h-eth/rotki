import logging
from typing import TYPE_CHECKING, NamedTuple, Optional

from rotkehlchen.chain.ethereum.modules.convex.constants import BOOSTER
from rotkehlchen.chain.evm.constants import ZERO_ADDRESS
from rotkehlchen.chain.evm.contracts import EvmContract
from rotkehlchen.chain.evm.decoding.interfaces import READ_CACHE_DATA_TYPE
from rotkehlchen.chain.evm.types import string_to_evm_address
from rotkehlchen.db.addressbook import DBAddressbook
from rotkehlchen.db.drivers.gevent import DBCursor
from rotkehlchen.errors.misc import InputError, RemoteError
from rotkehlchen.globaldb.cache import (
    globaldb_get_general_cache_like,
    globaldb_get_general_cache_values,
    globaldb_get_unique_cache_value,
    globaldb_set_general_cache_values,
    globaldb_set_unique_cache_value,
)
from rotkehlchen.globaldb.handler import GlobalDBHandler
from rotkehlchen.logging import RotkehlchenLogsAdapter
from rotkehlchen.types import AddressbookEntry, CacheType, ChecksumEvmAddress, SupportedBlockchain
from rotkehlchen.utils.misc import hex_or_bytes_to_address

if TYPE_CHECKING:
    from rotkehlchen.chain.ethereum.node_inquirer import EthereumInquirer
    from rotkehlchen.db.dbhandler import DBHandler

logger = logging.getLogger(__name__)
log = RotkehlchenLogsAdapter(logger)


class ConvexPoolData(NamedTuple):
    pool_address: ChecksumEvmAddress
    token_symbol: str
    virtual_pools: Optional[list[ChecksumEvmAddress]]


# TODO: resolve return type difference
def read_convex_reward_pools() -> READ_CACHE_DATA_TYPE:
    """Reads globaldb cache and returns:
    - A dictionary of all known reward pools (address -> symbol)
    - A set of all known virtual reward pools addresses

    Doesn't raise anything unless cache entries were inserted incorrectly.
    """
    with GlobalDBHandler().conn.read_ctx() as cursor:
        pools = {}
        virtual_pools = set()
        pool_addresses = globaldb_get_general_cache_values(
            cursor=cursor,
            key_parts=(CacheType.CONVEX_REWARD_POOLS,),
        )
        for pool_address in pool_addresses:
            pool_symbol = globaldb_get_unique_cache_value(
                cursor=cursor,
                key_parts=(CacheType.CONVEX_REWARD_POOL_SYMBOL, pool_address),
            )
            if pool_symbol is None:
                continue
            pools[pool_address] = pool_symbol

            virtual_pool_addresses = globaldb_get_general_cache_like(
                cursor=cursor,
                key_parts=(CacheType.CONVEX_VIRTUAL_REWARD_POOLS, pool_address),
            )
            if len(virtual_pool_addresses) > 0:
                for address in virtual_pool_addresses:
                    virtual_pools.add(string_to_evm_address(address))

    return pools, virtual_pools


def save_convex_data_to_cache(
        write_cursor: DBCursor,
        database: 'DBHandler',
        new_data: list[ConvexPoolData] | None,
) -> None:
    """Stores data about Convex reward and virtual reward pools"""
    db_addressbook = DBAddressbook(db_handler=database)
    for pool in new_data:
        addressbook_entries = [AddressbookEntry(
            address=pool.pool_address,
            name=f'Convex reward pool for {pool.token_symbol}',
            blockchain=SupportedBlockchain.ETHEREUM,
        )]
        try:
            db_addressbook.add_addressbook_entries(
                write_cursor=write_cursor,
                entries=addressbook_entries,
            )
        except InputError as e:
            log.debug(
                f'Convex address book names for pool {pool.pool_address} were not added. '
                f'Probably names were added by the user earlier. {e}')

        globaldb_set_general_cache_values(
            write_cursor=write_cursor,
            key_parts=(CacheType.CONVEX_REWARD_POOLS,),
            values=[pool.pool_address],
        )

        globaldb_set_unique_cache_value(
            write_cursor=write_cursor,
            key_parts=(CacheType.CONVEX_REWARD_POOL_SYMBOL, pool.pool_address),
            values=[pool.token_symbol],
        )

        if len(pool.virtual_pools) > 0:
            for idx, virtual_pool in enumerate(pool.virtual_pools):
                globaldb_set_general_cache_values(
                    write_cursor=write_cursor,
                    key_parts=(CacheType.CONVEX_VIRTUAL_REWARD_POOLS, pool.pool_address, str(idx)),
                    values=[virtual_pool],
                )


def query_convex_data_from_chain(
        ethereum: 'EthereumInquirer',
        existing_pools: list[ChecksumEvmAddress],
) -> Optional[list[ConvexPoolData]]:
    """
    Query Booster contract and fetch all reward pools
    and related virtual reward pools if they exist.

    May raise:
    - RemoteError if failed to query chain
    """
    booster_contract = ethereum.contracts.contract(BOOSTER)
    pools_count = booster_contract.call(
        node_inquirer=ethereum,
        method_name='poolLength',
    )
    calls_to_booster = [(
        booster_contract.address,
        booster_contract.encode('poolInfo', [x]),
    ) for x in range(pools_count)]
    booster_result = ethereum.multicall(
        calls=calls_to_booster,
    )
    convex_rewards_addrs = []
    convex_lp_tokens_addrs = []
    lp_tokens_contract = EvmContract(  # only need it to encode and decode
        address=ZERO_ADDRESS,
        abi=ethereum.contracts.abi('CONVEX_LP_TOKEN'),
        deployed_block=0,
    )
    for single_booster_result in booster_result:
        lp_token_addr = hex_or_bytes_to_address(single_booster_result[0:32])
        crv_rewards = hex_or_bytes_to_address(single_booster_result[3 * 32:4 * 32])
        convex_rewards_addrs.append(crv_rewards)
        convex_lp_tokens_addrs.append(lp_token_addr)

    calls_to_lp_tokens = [(lp_token_addr, lp_tokens_contract.encode('symbol')) for lp_token_addr in convex_lp_tokens_addrs]  # noqa: E501
    lp_tokens_result = ethereum.multicall(
        calls=calls_to_lp_tokens,
    )

    queried_convex_pools_info = {}
    for convex_reward_addr, single_lp_token_result in zip(convex_rewards_addrs, lp_tokens_result):
        decoded_lp_token_result = lp_tokens_contract.decode(single_lp_token_result, 'symbol')
        queried_convex_pools_info[convex_reward_addr] = decoded_lp_token_result[0]

    if queried_convex_pools_info != existing_pools:
        added_pools_addrs = queried_convex_pools_info.keys() - existing_pools.keys()
        added_pools = {addr: queried_convex_pools_info[addr] for addr in added_pools_addrs}

    # TODO: make a multicall to all reward pools, fetch extraRewardsLength() and if positive, then collect all addresses from extraRewards()  # noqa: E501

    return added_pools


def query_convex_data(inquirer: 'EthereumInquirer') -> Optional[list[ConvexPoolData]]:
    """Query Convex reward pools and virtual pools.

    May raise:
    - RemoteError if failed to query etherscan or node
    """
    with GlobalDBHandler().conn.read_ctx() as cursor:
        existing_pools = [
            string_to_evm_address(address)
            for address in globaldb_get_general_cache_like(cursor=cursor, key_parts=(CacheType.CONVEX_REWARD_POOLS,))  # noqa: E501
        ]
    try:
        pools_data = query_convex_data_from_chain(
            ethereum=inquirer,
            existing_pools=existing_pools,
        )
    except RemoteError as err:
        log.error(f'Could not query chain for curve pools due to: {err}')
        return None

    if pools_data is None:
        return None

    # TODO: check if ensure_curve_tokens_existence() call is needed
    return pools_data
