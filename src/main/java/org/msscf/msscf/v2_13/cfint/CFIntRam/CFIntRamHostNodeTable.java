
// Description: Java 11 in-memory RAM DbIO implementation for HostNode.

/*
 *	org.msscf.msscf.CFInt
 *
 *	Copyright (c) 2020 Mark Stephen Sobkow
 *	
 *	MSS Code Factory CFSec 2.13 Security Essentials
 *	
 *	Copyright 2020-2021 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *
 *	Manufactured by MSS Code Factory 2.12
 */

package org.msscf.msscf.v2_13.cfint.CFIntRam;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.msscf.msscf.v2_13.cflib.CFLib.*;
import org.msscf.msscf.v2_13.cfsec.CFSec.*;
import org.msscf.msscf.v2_13.cfint.CFInt.*;
import org.msscf.msscf.v2_13.cfint.CFIntObj.*;
import org.msscf.msscf.v2_13.cfsec.CFSecObj.*;
import org.msscf.msscf.v2_13.cfint.CFIntObj.*;

/*
 *	CFIntRamHostNodeTable in-memory RAM DbIO implementation
 *	for HostNode.
 */
public class CFIntRamHostNodeTable
	implements ICFIntHostNodeTable
{
	private ICFIntSchema schema;
	private Map< CFSecHostNodePKey,
				CFSecHostNodeBuff > dictByPKey
		= new HashMap< CFSecHostNodePKey,
				CFSecHostNodeBuff >();
	private Map< CFSecHostNodeByClusterIdxKey,
				Map< CFSecHostNodePKey,
					CFSecHostNodeBuff >> dictByClusterIdx
		= new HashMap< CFSecHostNodeByClusterIdxKey,
				Map< CFSecHostNodePKey,
					CFSecHostNodeBuff >>();
	private Map< CFSecHostNodeByUDescrIdxKey,
			CFSecHostNodeBuff > dictByUDescrIdx
		= new HashMap< CFSecHostNodeByUDescrIdxKey,
			CFSecHostNodeBuff >();
	private Map< CFSecHostNodeByHostNameIdxKey,
			CFSecHostNodeBuff > dictByHostNameIdx
		= new HashMap< CFSecHostNodeByHostNameIdxKey,
			CFSecHostNodeBuff >();

	public CFIntRamHostNodeTable( ICFIntSchema argSchema ) {
		schema = argSchema;
	}

	public void createHostNode( CFSecAuthorization Authorization,
		CFSecHostNodeBuff Buff )
	{
		final String S_ProcName = "createHostNode";
		CFSecHostNodePKey pkey = schema.getFactoryHostNode().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredHostNodeId( ((CFIntRamClusterTable)schema.getTableCluster()).nextHostNodeIdGen( Authorization,
			Buff.getRequiredClusterId() ) );
		Buff.setRequiredClusterId( pkey.getRequiredClusterId() );
		Buff.setRequiredHostNodeId( pkey.getRequiredHostNodeId() );
		CFSecHostNodeByClusterIdxKey keyClusterIdx = schema.getFactoryHostNode().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecHostNodeByUDescrIdxKey keyUDescrIdx = schema.getFactoryHostNode().newUDescrIdxKey();
		keyUDescrIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUDescrIdx.setRequiredDescription( Buff.getRequiredDescription() );

		CFSecHostNodeByHostNameIdxKey keyHostNameIdx = schema.getFactoryHostNode().newHostNameIdxKey();
		keyHostNameIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyHostNameIdx.setRequiredHostName( Buff.getRequiredHostName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUDescrIdx.containsKey( keyUDescrIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"HostNodeUDescrIdx",
				keyUDescrIdx );
		}

		if( dictByHostNameIdx.containsKey( keyHostNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"HostNodeUHostNameIdx",
				keyHostNameIdx );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"HostNodeCluster",
						"Cluster",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecHostNodePKey, CFSecHostNodeBuff > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< CFSecHostNodePKey, CFSecHostNodeBuff >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

		dictByUDescrIdx.put( keyUDescrIdx, Buff );

		dictByHostNameIdx.put( keyHostNameIdx, Buff );

	}

	public CFSecHostNodeBuff readDerived( CFSecAuthorization Authorization,
		CFSecHostNodePKey PKey )
	{
		final String S_ProcName = "CFIntRamHostNode.readDerived";
		CFSecHostNodePKey key = schema.getFactoryHostNode().newPKey();
		key.setRequiredClusterId( PKey.getRequiredClusterId() );
		key.setRequiredHostNodeId( PKey.getRequiredHostNodeId() );
		CFSecHostNodeBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecHostNodeBuff lockDerived( CFSecAuthorization Authorization,
		CFSecHostNodePKey PKey )
	{
		final String S_ProcName = "CFIntRamHostNode.readDerived";
		CFSecHostNodePKey key = schema.getFactoryHostNode().newPKey();
		key.setRequiredClusterId( PKey.getRequiredClusterId() );
		key.setRequiredHostNodeId( PKey.getRequiredHostNodeId() );
		CFSecHostNodeBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecHostNodeBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFIntRamHostNode.readAllDerived";
		CFSecHostNodeBuff[] retList = new CFSecHostNodeBuff[ dictByPKey.values().size() ];
		Iterator< CFSecHostNodeBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecHostNodeBuff[] readDerivedByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFIntRamHostNode.readDerivedByClusterIdx";
		CFSecHostNodeByClusterIdxKey key = schema.getFactoryHostNode().newClusterIdxKey();
		key.setRequiredClusterId( ClusterId );

		CFSecHostNodeBuff[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< CFSecHostNodePKey, CFSecHostNodeBuff > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new CFSecHostNodeBuff[ subdictClusterIdx.size() ];
			Iterator< CFSecHostNodeBuff > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecHostNodePKey, CFSecHostNodeBuff > subdictClusterIdx
				= new HashMap< CFSecHostNodePKey, CFSecHostNodeBuff >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new CFSecHostNodeBuff[0];
		}
		return( recArray );
	}

	public CFSecHostNodeBuff readDerivedByUDescrIdx( CFSecAuthorization Authorization,
		long ClusterId,
		String Description )
	{
		final String S_ProcName = "CFIntRamHostNode.readDerivedByUDescrIdx";
		CFSecHostNodeByUDescrIdxKey key = schema.getFactoryHostNode().newUDescrIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredDescription( Description );

		CFSecHostNodeBuff buff;
		if( dictByUDescrIdx.containsKey( key ) ) {
			buff = dictByUDescrIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecHostNodeBuff readDerivedByHostNameIdx( CFSecAuthorization Authorization,
		long ClusterId,
		String HostName )
	{
		final String S_ProcName = "CFIntRamHostNode.readDerivedByHostNameIdx";
		CFSecHostNodeByHostNameIdxKey key = schema.getFactoryHostNode().newHostNameIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredHostName( HostName );

		CFSecHostNodeBuff buff;
		if( dictByHostNameIdx.containsKey( key ) ) {
			buff = dictByHostNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecHostNodeBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		long ClusterId,
		long HostNodeId )
	{
		final String S_ProcName = "CFIntRamHostNode.readDerivedByIdIdx() ";
		CFSecHostNodePKey key = schema.getFactoryHostNode().newPKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredHostNodeId( HostNodeId );

		CFSecHostNodeBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecHostNodeBuff readBuff( CFSecAuthorization Authorization,
		CFSecHostNodePKey PKey )
	{
		final String S_ProcName = "CFIntRamHostNode.readBuff";
		CFSecHostNodeBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a002" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecHostNodeBuff lockBuff( CFSecAuthorization Authorization,
		CFSecHostNodePKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecHostNodeBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a002" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecHostNodeBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFIntRamHostNode.readAllBuff";
		CFSecHostNodeBuff buff;
		ArrayList<CFSecHostNodeBuff> filteredList = new ArrayList<CFSecHostNodeBuff>();
		CFSecHostNodeBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a002" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecHostNodeBuff[0] ) );
	}

	/**
	 *	Read a page of all the specific HostNode buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific HostNode instances in the database accessible for the Authorization.
	 */
	public CFSecHostNodeBuff[] pageAllBuff( CFSecAuthorization Authorization,
		Long priorClusterId,
		Long priorHostNodeId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public CFSecHostNodeBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		long ClusterId,
		long HostNodeId )
	{
		final String S_ProcName = "CFIntRamHostNode.readBuffByIdIdx() ";
		CFSecHostNodeBuff buff = readDerivedByIdIdx( Authorization,
			ClusterId,
			HostNodeId );
		if( ( buff != null ) && buff.getClassCode().equals( "a002" ) ) {
			return( (CFSecHostNodeBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecHostNodeBuff[] readBuffByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFIntRamHostNode.readBuffByClusterIdx() ";
		CFSecHostNodeBuff buff;
		ArrayList<CFSecHostNodeBuff> filteredList = new ArrayList<CFSecHostNodeBuff>();
		CFSecHostNodeBuff[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a002" ) ) {
				filteredList.add( (CFSecHostNodeBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecHostNodeBuff[0] ) );
	}

	public CFSecHostNodeBuff readBuffByUDescrIdx( CFSecAuthorization Authorization,
		long ClusterId,
		String Description )
	{
		final String S_ProcName = "CFIntRamHostNode.readBuffByUDescrIdx() ";
		CFSecHostNodeBuff buff = readDerivedByUDescrIdx( Authorization,
			ClusterId,
			Description );
		if( ( buff != null ) && buff.getClassCode().equals( "a002" ) ) {
			return( (CFSecHostNodeBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecHostNodeBuff readBuffByHostNameIdx( CFSecAuthorization Authorization,
		long ClusterId,
		String HostName )
	{
		final String S_ProcName = "CFIntRamHostNode.readBuffByHostNameIdx() ";
		CFSecHostNodeBuff buff = readDerivedByHostNameIdx( Authorization,
			ClusterId,
			HostName );
		if( ( buff != null ) && buff.getClassCode().equals( "a002" ) ) {
			return( (CFSecHostNodeBuff)buff );
		}
		else {
			return( null );
		}
	}

	/**
	 *	Read a page array of the specific HostNode buffer instances identified by the duplicate key ClusterIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argClusterId	The HostNode key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecHostNodeBuff[] pageBuffByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId,
		Long priorClusterId,
		Long priorHostNodeId )
	{
		final String S_ProcName = "pageBuffByClusterIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public void updateHostNode( CFSecAuthorization Authorization,
		CFSecHostNodeBuff Buff )
	{
		CFSecHostNodePKey pkey = schema.getFactoryHostNode().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredHostNodeId( Buff.getRequiredHostNodeId() );
		CFSecHostNodeBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateHostNode",
				"Existing record not found",
				"HostNode",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateHostNode",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecHostNodeByClusterIdxKey existingKeyClusterIdx = schema.getFactoryHostNode().newClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecHostNodeByClusterIdxKey newKeyClusterIdx = schema.getFactoryHostNode().newClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecHostNodeByUDescrIdxKey existingKeyUDescrIdx = schema.getFactoryHostNode().newUDescrIdxKey();
		existingKeyUDescrIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUDescrIdx.setRequiredDescription( existing.getRequiredDescription() );

		CFSecHostNodeByUDescrIdxKey newKeyUDescrIdx = schema.getFactoryHostNode().newUDescrIdxKey();
		newKeyUDescrIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUDescrIdx.setRequiredDescription( Buff.getRequiredDescription() );

		CFSecHostNodeByHostNameIdxKey existingKeyHostNameIdx = schema.getFactoryHostNode().newHostNameIdxKey();
		existingKeyHostNameIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyHostNameIdx.setRequiredHostName( existing.getRequiredHostName() );

		CFSecHostNodeByHostNameIdxKey newKeyHostNameIdx = schema.getFactoryHostNode().newHostNameIdxKey();
		newKeyHostNameIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyHostNameIdx.setRequiredHostName( Buff.getRequiredHostName() );

		// Check unique indexes

		if( ! existingKeyUDescrIdx.equals( newKeyUDescrIdx ) ) {
			if( dictByUDescrIdx.containsKey( newKeyUDescrIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateHostNode",
					"HostNodeUDescrIdx",
					newKeyUDescrIdx );
			}
		}

		if( ! existingKeyHostNameIdx.equals( newKeyHostNameIdx ) ) {
			if( dictByHostNameIdx.containsKey( newKeyHostNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateHostNode",
					"HostNodeUHostNameIdx",
					newKeyHostNameIdx );
			}
		}

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateHostNode",
						"Container",
						"HostNodeCluster",
						"Cluster",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecHostNodePKey, CFSecHostNodeBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByClusterIdx.get( existingKeyClusterIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByClusterIdx.containsKey( newKeyClusterIdx ) ) {
			subdict = dictByClusterIdx.get( newKeyClusterIdx );
		}
		else {
			subdict = new HashMap< CFSecHostNodePKey, CFSecHostNodeBuff >();
			dictByClusterIdx.put( newKeyClusterIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUDescrIdx.remove( existingKeyUDescrIdx );
		dictByUDescrIdx.put( newKeyUDescrIdx, Buff );

		dictByHostNameIdx.remove( existingKeyHostNameIdx );
		dictByHostNameIdx.put( newKeyHostNameIdx, Buff );

	}

	public void deleteHostNode( CFSecAuthorization Authorization,
		CFSecHostNodeBuff Buff )
	{
		final String S_ProcName = "CFIntRamHostNodeTable.deleteHostNode() ";
		String classCode;
		CFSecHostNodePKey pkey = schema.getFactoryHostNode().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredHostNodeId( Buff.getRequiredHostNodeId() );
		CFSecHostNodeBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteHostNode",
				pkey );
		}
					schema.getTableService().deleteServiceByHostIdx( Authorization,
						existing.getRequiredClusterId(),
						existing.getRequiredHostNodeId() );
		CFSecHostNodeByClusterIdxKey keyClusterIdx = schema.getFactoryHostNode().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecHostNodeByUDescrIdxKey keyUDescrIdx = schema.getFactoryHostNode().newUDescrIdxKey();
		keyUDescrIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUDescrIdx.setRequiredDescription( existing.getRequiredDescription() );

		CFSecHostNodeByHostNameIdxKey keyHostNameIdx = schema.getFactoryHostNode().newHostNameIdxKey();
		keyHostNameIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyHostNameIdx.setRequiredHostName( existing.getRequiredHostName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecHostNodePKey, CFSecHostNodeBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

		dictByUDescrIdx.remove( keyUDescrIdx );

		dictByHostNameIdx.remove( keyHostNameIdx );

	}
	public void deleteHostNodeByIdIdx( CFSecAuthorization Authorization,
		long argClusterId,
		long argHostNodeId )
	{
		CFSecHostNodePKey key = schema.getFactoryHostNode().newPKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredHostNodeId( argHostNodeId );
		deleteHostNodeByIdIdx( Authorization, key );
	}

	public void deleteHostNodeByIdIdx( CFSecAuthorization Authorization,
		CFSecHostNodePKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecHostNodeBuff cur;
		LinkedList<CFSecHostNodeBuff> matchSet = new LinkedList<CFSecHostNodeBuff>();
		Iterator<CFSecHostNodeBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecHostNodeBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableHostNode().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredHostNodeId() );
			deleteHostNode( Authorization, cur );
		}
	}

	public void deleteHostNodeByClusterIdx( CFSecAuthorization Authorization,
		long argClusterId )
	{
		CFSecHostNodeByClusterIdxKey key = schema.getFactoryHostNode().newClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteHostNodeByClusterIdx( Authorization, key );
	}

	public void deleteHostNodeByClusterIdx( CFSecAuthorization Authorization,
		CFSecHostNodeByClusterIdxKey argKey )
	{
		CFSecHostNodeBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecHostNodeBuff> matchSet = new LinkedList<CFSecHostNodeBuff>();
		Iterator<CFSecHostNodeBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecHostNodeBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableHostNode().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredHostNodeId() );
			deleteHostNode( Authorization, cur );
		}
	}

	public void deleteHostNodeByUDescrIdx( CFSecAuthorization Authorization,
		long argClusterId,
		String argDescription )
	{
		CFSecHostNodeByUDescrIdxKey key = schema.getFactoryHostNode().newUDescrIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredDescription( argDescription );
		deleteHostNodeByUDescrIdx( Authorization, key );
	}

	public void deleteHostNodeByUDescrIdx( CFSecAuthorization Authorization,
		CFSecHostNodeByUDescrIdxKey argKey )
	{
		CFSecHostNodeBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecHostNodeBuff> matchSet = new LinkedList<CFSecHostNodeBuff>();
		Iterator<CFSecHostNodeBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecHostNodeBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableHostNode().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredHostNodeId() );
			deleteHostNode( Authorization, cur );
		}
	}

	public void deleteHostNodeByHostNameIdx( CFSecAuthorization Authorization,
		long argClusterId,
		String argHostName )
	{
		CFSecHostNodeByHostNameIdxKey key = schema.getFactoryHostNode().newHostNameIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredHostName( argHostName );
		deleteHostNodeByHostNameIdx( Authorization, key );
	}

	public void deleteHostNodeByHostNameIdx( CFSecAuthorization Authorization,
		CFSecHostNodeByHostNameIdxKey argKey )
	{
		CFSecHostNodeBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecHostNodeBuff> matchSet = new LinkedList<CFSecHostNodeBuff>();
		Iterator<CFSecHostNodeBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecHostNodeBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableHostNode().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredHostNodeId() );
			deleteHostNode( Authorization, cur );
		}
	}

	public void releasePreparedStatements() {
	}
}
