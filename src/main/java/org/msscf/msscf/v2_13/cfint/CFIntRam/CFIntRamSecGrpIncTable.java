
// Description: Java 11 in-memory RAM DbIO implementation for SecGrpInc.

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
 *	CFIntRamSecGrpIncTable in-memory RAM DbIO implementation
 *	for SecGrpInc.
 */
public class CFIntRamSecGrpIncTable
	implements ICFIntSecGrpIncTable
{
	private ICFIntSchema schema;
	private Map< CFSecSecGrpIncPKey,
				CFSecSecGrpIncBuff > dictByPKey
		= new HashMap< CFSecSecGrpIncPKey,
				CFSecSecGrpIncBuff >();
	private Map< CFSecSecGrpIncByClusterIdxKey,
				Map< CFSecSecGrpIncPKey,
					CFSecSecGrpIncBuff >> dictByClusterIdx
		= new HashMap< CFSecSecGrpIncByClusterIdxKey,
				Map< CFSecSecGrpIncPKey,
					CFSecSecGrpIncBuff >>();
	private Map< CFSecSecGrpIncByGroupIdxKey,
				Map< CFSecSecGrpIncPKey,
					CFSecSecGrpIncBuff >> dictByGroupIdx
		= new HashMap< CFSecSecGrpIncByGroupIdxKey,
				Map< CFSecSecGrpIncPKey,
					CFSecSecGrpIncBuff >>();
	private Map< CFSecSecGrpIncByIncludeIdxKey,
				Map< CFSecSecGrpIncPKey,
					CFSecSecGrpIncBuff >> dictByIncludeIdx
		= new HashMap< CFSecSecGrpIncByIncludeIdxKey,
				Map< CFSecSecGrpIncPKey,
					CFSecSecGrpIncBuff >>();
	private Map< CFSecSecGrpIncByUIncludeIdxKey,
			CFSecSecGrpIncBuff > dictByUIncludeIdx
		= new HashMap< CFSecSecGrpIncByUIncludeIdxKey,
			CFSecSecGrpIncBuff >();

	public CFIntRamSecGrpIncTable( ICFIntSchema argSchema ) {
		schema = argSchema;
	}

	public void createSecGrpInc( CFSecAuthorization Authorization,
		CFSecSecGrpIncBuff Buff )
	{
		final String S_ProcName = "createSecGrpInc";
		CFSecSecGrpIncPKey pkey = schema.getFactorySecGrpInc().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredSecGrpIncId( ((CFIntRamClusterTable)schema.getTableCluster()).nextSecGrpIncIdGen( Authorization,
			Buff.getRequiredClusterId() ) );
		Buff.setRequiredClusterId( pkey.getRequiredClusterId() );
		Buff.setRequiredSecGrpIncId( pkey.getRequiredSecGrpIncId() );
		CFSecSecGrpIncByClusterIdxKey keyClusterIdx = schema.getFactorySecGrpInc().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecSecGrpIncByGroupIdxKey keyGroupIdx = schema.getFactorySecGrpInc().newGroupIdxKey();
		keyGroupIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyGroupIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );

		CFSecSecGrpIncByIncludeIdxKey keyIncludeIdx = schema.getFactorySecGrpInc().newIncludeIdxKey();
		keyIncludeIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyIncludeIdx.setRequiredIncludeGroupId( Buff.getRequiredIncludeGroupId() );

		CFSecSecGrpIncByUIncludeIdxKey keyUIncludeIdx = schema.getFactorySecGrpInc().newUIncludeIdxKey();
		keyUIncludeIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUIncludeIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );
		keyUIncludeIdx.setRequiredIncludeGroupId( Buff.getRequiredIncludeGroupId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUIncludeIdx.containsKey( keyUIncludeIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecGrpIncUIncludeIdx",
				keyUIncludeIdx );
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
						"Owner",
						"SecGrpIncCluster",
						"Cluster",
						null );
				}
			}
		}

		{
			boolean allNull = true;
			allNull = false;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId(),
						Buff.getRequiredSecGroupId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"SecGrpIncGroup",
						"SecGroup",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

		Map< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff > subdictGroupIdx;
		if( dictByGroupIdx.containsKey( keyGroupIdx ) ) {
			subdictGroupIdx = dictByGroupIdx.get( keyGroupIdx );
		}
		else {
			subdictGroupIdx = new HashMap< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff >();
			dictByGroupIdx.put( keyGroupIdx, subdictGroupIdx );
		}
		subdictGroupIdx.put( pkey, Buff );

		Map< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff > subdictIncludeIdx;
		if( dictByIncludeIdx.containsKey( keyIncludeIdx ) ) {
			subdictIncludeIdx = dictByIncludeIdx.get( keyIncludeIdx );
		}
		else {
			subdictIncludeIdx = new HashMap< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff >();
			dictByIncludeIdx.put( keyIncludeIdx, subdictIncludeIdx );
		}
		subdictIncludeIdx.put( pkey, Buff );

		dictByUIncludeIdx.put( keyUIncludeIdx, Buff );

	}

	public CFSecSecGrpIncBuff readDerived( CFSecAuthorization Authorization,
		CFSecSecGrpIncPKey PKey )
	{
		final String S_ProcName = "CFIntRamSecGrpInc.readDerived";
		CFSecSecGrpIncPKey key = schema.getFactorySecGrpInc().newPKey();
		key.setRequiredClusterId( PKey.getRequiredClusterId() );
		key.setRequiredSecGrpIncId( PKey.getRequiredSecGrpIncId() );
		CFSecSecGrpIncBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGrpIncBuff lockDerived( CFSecAuthorization Authorization,
		CFSecSecGrpIncPKey PKey )
	{
		final String S_ProcName = "CFIntRamSecGrpInc.readDerived";
		CFSecSecGrpIncPKey key = schema.getFactorySecGrpInc().newPKey();
		key.setRequiredClusterId( PKey.getRequiredClusterId() );
		key.setRequiredSecGrpIncId( PKey.getRequiredSecGrpIncId() );
		CFSecSecGrpIncBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGrpIncBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFIntRamSecGrpInc.readAllDerived";
		CFSecSecGrpIncBuff[] retList = new CFSecSecGrpIncBuff[ dictByPKey.values().size() ];
		Iterator< CFSecSecGrpIncBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecSecGrpIncBuff[] readDerivedByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFIntRamSecGrpInc.readDerivedByClusterIdx";
		CFSecSecGrpIncByClusterIdxKey key = schema.getFactorySecGrpInc().newClusterIdxKey();
		key.setRequiredClusterId( ClusterId );

		CFSecSecGrpIncBuff[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new CFSecSecGrpIncBuff[ subdictClusterIdx.size() ];
			Iterator< CFSecSecGrpIncBuff > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff > subdictClusterIdx
				= new HashMap< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new CFSecSecGrpIncBuff[0];
		}
		return( recArray );
	}

	public CFSecSecGrpIncBuff[] readDerivedByGroupIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecGroupId )
	{
		final String S_ProcName = "CFIntRamSecGrpInc.readDerivedByGroupIdx";
		CFSecSecGrpIncByGroupIdxKey key = schema.getFactorySecGrpInc().newGroupIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredSecGroupId( SecGroupId );

		CFSecSecGrpIncBuff[] recArray;
		if( dictByGroupIdx.containsKey( key ) ) {
			Map< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff > subdictGroupIdx
				= dictByGroupIdx.get( key );
			recArray = new CFSecSecGrpIncBuff[ subdictGroupIdx.size() ];
			Iterator< CFSecSecGrpIncBuff > iter = subdictGroupIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff > subdictGroupIdx
				= new HashMap< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff >();
			dictByGroupIdx.put( key, subdictGroupIdx );
			recArray = new CFSecSecGrpIncBuff[0];
		}
		return( recArray );
	}

	public CFSecSecGrpIncBuff[] readDerivedByIncludeIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int IncludeGroupId )
	{
		final String S_ProcName = "CFIntRamSecGrpInc.readDerivedByIncludeIdx";
		CFSecSecGrpIncByIncludeIdxKey key = schema.getFactorySecGrpInc().newIncludeIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredIncludeGroupId( IncludeGroupId );

		CFSecSecGrpIncBuff[] recArray;
		if( dictByIncludeIdx.containsKey( key ) ) {
			Map< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff > subdictIncludeIdx
				= dictByIncludeIdx.get( key );
			recArray = new CFSecSecGrpIncBuff[ subdictIncludeIdx.size() ];
			Iterator< CFSecSecGrpIncBuff > iter = subdictIncludeIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff > subdictIncludeIdx
				= new HashMap< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff >();
			dictByIncludeIdx.put( key, subdictIncludeIdx );
			recArray = new CFSecSecGrpIncBuff[0];
		}
		return( recArray );
	}

	public CFSecSecGrpIncBuff readDerivedByUIncludeIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecGroupId,
		int IncludeGroupId )
	{
		final String S_ProcName = "CFIntRamSecGrpInc.readDerivedByUIncludeIdx";
		CFSecSecGrpIncByUIncludeIdxKey key = schema.getFactorySecGrpInc().newUIncludeIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredSecGroupId( SecGroupId );
		key.setRequiredIncludeGroupId( IncludeGroupId );

		CFSecSecGrpIncBuff buff;
		if( dictByUIncludeIdx.containsKey( key ) ) {
			buff = dictByUIncludeIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGrpIncBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		long ClusterId,
		long SecGrpIncId )
	{
		final String S_ProcName = "CFIntRamSecGrpInc.readDerivedByIdIdx() ";
		CFSecSecGrpIncPKey key = schema.getFactorySecGrpInc().newPKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredSecGrpIncId( SecGrpIncId );

		CFSecSecGrpIncBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGrpIncBuff readBuff( CFSecAuthorization Authorization,
		CFSecSecGrpIncPKey PKey )
	{
		final String S_ProcName = "CFIntRamSecGrpInc.readBuff";
		CFSecSecGrpIncBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a00e" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGrpIncBuff lockBuff( CFSecAuthorization Authorization,
		CFSecSecGrpIncPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecSecGrpIncBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a00e" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGrpIncBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFIntRamSecGrpInc.readAllBuff";
		CFSecSecGrpIncBuff buff;
		ArrayList<CFSecSecGrpIncBuff> filteredList = new ArrayList<CFSecSecGrpIncBuff>();
		CFSecSecGrpIncBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00e" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGrpIncBuff[0] ) );
	}

	/**
	 *	Read a page of all the specific SecGrpInc buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecGrpInc instances in the database accessible for the Authorization.
	 */
	public CFSecSecGrpIncBuff[] pageAllBuff( CFSecAuthorization Authorization,
		Long priorClusterId,
		Long priorSecGrpIncId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public CFSecSecGrpIncBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		long ClusterId,
		long SecGrpIncId )
	{
		final String S_ProcName = "CFIntRamSecGrpInc.readBuffByIdIdx() ";
		CFSecSecGrpIncBuff buff = readDerivedByIdIdx( Authorization,
			ClusterId,
			SecGrpIncId );
		if( ( buff != null ) && buff.getClassCode().equals( "a00e" ) ) {
			return( (CFSecSecGrpIncBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecSecGrpIncBuff[] readBuffByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFIntRamSecGrpInc.readBuffByClusterIdx() ";
		CFSecSecGrpIncBuff buff;
		ArrayList<CFSecSecGrpIncBuff> filteredList = new ArrayList<CFSecSecGrpIncBuff>();
		CFSecSecGrpIncBuff[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00e" ) ) {
				filteredList.add( (CFSecSecGrpIncBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGrpIncBuff[0] ) );
	}

	public CFSecSecGrpIncBuff[] readBuffByGroupIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecGroupId )
	{
		final String S_ProcName = "CFIntRamSecGrpInc.readBuffByGroupIdx() ";
		CFSecSecGrpIncBuff buff;
		ArrayList<CFSecSecGrpIncBuff> filteredList = new ArrayList<CFSecSecGrpIncBuff>();
		CFSecSecGrpIncBuff[] buffList = readDerivedByGroupIdx( Authorization,
			ClusterId,
			SecGroupId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00e" ) ) {
				filteredList.add( (CFSecSecGrpIncBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGrpIncBuff[0] ) );
	}

	public CFSecSecGrpIncBuff[] readBuffByIncludeIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int IncludeGroupId )
	{
		final String S_ProcName = "CFIntRamSecGrpInc.readBuffByIncludeIdx() ";
		CFSecSecGrpIncBuff buff;
		ArrayList<CFSecSecGrpIncBuff> filteredList = new ArrayList<CFSecSecGrpIncBuff>();
		CFSecSecGrpIncBuff[] buffList = readDerivedByIncludeIdx( Authorization,
			ClusterId,
			IncludeGroupId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00e" ) ) {
				filteredList.add( (CFSecSecGrpIncBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGrpIncBuff[0] ) );
	}

	public CFSecSecGrpIncBuff readBuffByUIncludeIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecGroupId,
		int IncludeGroupId )
	{
		final String S_ProcName = "CFIntRamSecGrpInc.readBuffByUIncludeIdx() ";
		CFSecSecGrpIncBuff buff = readDerivedByUIncludeIdx( Authorization,
			ClusterId,
			SecGroupId,
			IncludeGroupId );
		if( ( buff != null ) && buff.getClassCode().equals( "a00e" ) ) {
			return( (CFSecSecGrpIncBuff)buff );
		}
		else {
			return( null );
		}
	}

	/**
	 *	Read a page array of the specific SecGrpInc buffer instances identified by the duplicate key ClusterIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argClusterId	The SecGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecGrpIncBuff[] pageBuffByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId,
		Long priorClusterId,
		Long priorSecGrpIncId )
	{
		final String S_ProcName = "pageBuffByClusterIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecGrpInc buffer instances identified by the duplicate key GroupIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argClusterId	The SecGrpInc key attribute of the instance generating the id.
	 *
	 *	@param	argSecGroupId	The SecGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecGrpIncBuff[] pageBuffByGroupIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecGroupId,
		Long priorClusterId,
		Long priorSecGrpIncId )
	{
		final String S_ProcName = "pageBuffByGroupIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecGrpInc buffer instances identified by the duplicate key IncludeIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argClusterId	The SecGrpInc key attribute of the instance generating the id.
	 *
	 *	@param	argIncludeGroupId	The SecGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecGrpIncBuff[] pageBuffByIncludeIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int IncludeGroupId,
		Long priorClusterId,
		Long priorSecGrpIncId )
	{
		final String S_ProcName = "pageBuffByIncludeIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public void updateSecGrpInc( CFSecAuthorization Authorization,
		CFSecSecGrpIncBuff Buff )
	{
		CFSecSecGrpIncPKey pkey = schema.getFactorySecGrpInc().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredSecGrpIncId( Buff.getRequiredSecGrpIncId() );
		CFSecSecGrpIncBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecGrpInc",
				"Existing record not found",
				"SecGrpInc",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecGrpInc",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecSecGrpIncByClusterIdxKey existingKeyClusterIdx = schema.getFactorySecGrpInc().newClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecSecGrpIncByClusterIdxKey newKeyClusterIdx = schema.getFactorySecGrpInc().newClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecSecGrpIncByGroupIdxKey existingKeyGroupIdx = schema.getFactorySecGrpInc().newGroupIdxKey();
		existingKeyGroupIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyGroupIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );

		CFSecSecGrpIncByGroupIdxKey newKeyGroupIdx = schema.getFactorySecGrpInc().newGroupIdxKey();
		newKeyGroupIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyGroupIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );

		CFSecSecGrpIncByIncludeIdxKey existingKeyIncludeIdx = schema.getFactorySecGrpInc().newIncludeIdxKey();
		existingKeyIncludeIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyIncludeIdx.setRequiredIncludeGroupId( existing.getRequiredIncludeGroupId() );

		CFSecSecGrpIncByIncludeIdxKey newKeyIncludeIdx = schema.getFactorySecGrpInc().newIncludeIdxKey();
		newKeyIncludeIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyIncludeIdx.setRequiredIncludeGroupId( Buff.getRequiredIncludeGroupId() );

		CFSecSecGrpIncByUIncludeIdxKey existingKeyUIncludeIdx = schema.getFactorySecGrpInc().newUIncludeIdxKey();
		existingKeyUIncludeIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUIncludeIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );
		existingKeyUIncludeIdx.setRequiredIncludeGroupId( existing.getRequiredIncludeGroupId() );

		CFSecSecGrpIncByUIncludeIdxKey newKeyUIncludeIdx = schema.getFactorySecGrpInc().newUIncludeIdxKey();
		newKeyUIncludeIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUIncludeIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );
		newKeyUIncludeIdx.setRequiredIncludeGroupId( Buff.getRequiredIncludeGroupId() );

		// Check unique indexes

		if( ! existingKeyUIncludeIdx.equals( newKeyUIncludeIdx ) ) {
			if( dictByUIncludeIdx.containsKey( newKeyUIncludeIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecGrpInc",
					"SecGrpIncUIncludeIdx",
					newKeyUIncludeIdx );
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
						"updateSecGrpInc",
						"Owner",
						"SecGrpIncCluster",
						"Cluster",
						null );
				}
			}
		}

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId(),
						Buff.getRequiredSecGroupId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecGrpInc",
						"Container",
						"SecGrpIncGroup",
						"SecGroup",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff > subdict;

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
			subdict = new HashMap< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff >();
			dictByClusterIdx.put( newKeyClusterIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByGroupIdx.get( existingKeyGroupIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByGroupIdx.containsKey( newKeyGroupIdx ) ) {
			subdict = dictByGroupIdx.get( newKeyGroupIdx );
		}
		else {
			subdict = new HashMap< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff >();
			dictByGroupIdx.put( newKeyGroupIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByIncludeIdx.get( existingKeyIncludeIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByIncludeIdx.containsKey( newKeyIncludeIdx ) ) {
			subdict = dictByIncludeIdx.get( newKeyIncludeIdx );
		}
		else {
			subdict = new HashMap< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff >();
			dictByIncludeIdx.put( newKeyIncludeIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUIncludeIdx.remove( existingKeyUIncludeIdx );
		dictByUIncludeIdx.put( newKeyUIncludeIdx, Buff );

	}

	public void deleteSecGrpInc( CFSecAuthorization Authorization,
		CFSecSecGrpIncBuff Buff )
	{
		final String S_ProcName = "CFIntRamSecGrpIncTable.deleteSecGrpInc() ";
		String classCode;
		CFSecSecGrpIncPKey pkey = schema.getFactorySecGrpInc().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredSecGrpIncId( Buff.getRequiredSecGrpIncId() );
		CFSecSecGrpIncBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecGrpInc",
				pkey );
		}
		CFSecSecGrpIncByClusterIdxKey keyClusterIdx = schema.getFactorySecGrpInc().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecSecGrpIncByGroupIdxKey keyGroupIdx = schema.getFactorySecGrpInc().newGroupIdxKey();
		keyGroupIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyGroupIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );

		CFSecSecGrpIncByIncludeIdxKey keyIncludeIdx = schema.getFactorySecGrpInc().newIncludeIdxKey();
		keyIncludeIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyIncludeIdx.setRequiredIncludeGroupId( existing.getRequiredIncludeGroupId() );

		CFSecSecGrpIncByUIncludeIdxKey keyUIncludeIdx = schema.getFactorySecGrpInc().newUIncludeIdxKey();
		keyUIncludeIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUIncludeIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );
		keyUIncludeIdx.setRequiredIncludeGroupId( existing.getRequiredIncludeGroupId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecSecGrpIncPKey, CFSecSecGrpIncBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

		subdict = dictByGroupIdx.get( keyGroupIdx );
		subdict.remove( pkey );

		subdict = dictByIncludeIdx.get( keyIncludeIdx );
		subdict.remove( pkey );

		dictByUIncludeIdx.remove( keyUIncludeIdx );

	}
	public void deleteSecGrpIncByIdIdx( CFSecAuthorization Authorization,
		long argClusterId,
		long argSecGrpIncId )
	{
		CFSecSecGrpIncPKey key = schema.getFactorySecGrpInc().newPKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredSecGrpIncId( argSecGrpIncId );
		deleteSecGrpIncByIdIdx( Authorization, key );
	}

	public void deleteSecGrpIncByIdIdx( CFSecAuthorization Authorization,
		CFSecSecGrpIncPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecSecGrpIncBuff cur;
		LinkedList<CFSecSecGrpIncBuff> matchSet = new LinkedList<CFSecSecGrpIncBuff>();
		Iterator<CFSecSecGrpIncBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGrpIncBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecGrpIncId() );
			deleteSecGrpInc( Authorization, cur );
		}
	}

	public void deleteSecGrpIncByClusterIdx( CFSecAuthorization Authorization,
		long argClusterId )
	{
		CFSecSecGrpIncByClusterIdxKey key = schema.getFactorySecGrpInc().newClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteSecGrpIncByClusterIdx( Authorization, key );
	}

	public void deleteSecGrpIncByClusterIdx( CFSecAuthorization Authorization,
		CFSecSecGrpIncByClusterIdxKey argKey )
	{
		CFSecSecGrpIncBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGrpIncBuff> matchSet = new LinkedList<CFSecSecGrpIncBuff>();
		Iterator<CFSecSecGrpIncBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGrpIncBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecGrpIncId() );
			deleteSecGrpInc( Authorization, cur );
		}
	}

	public void deleteSecGrpIncByGroupIdx( CFSecAuthorization Authorization,
		long argClusterId,
		int argSecGroupId )
	{
		CFSecSecGrpIncByGroupIdxKey key = schema.getFactorySecGrpInc().newGroupIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredSecGroupId( argSecGroupId );
		deleteSecGrpIncByGroupIdx( Authorization, key );
	}

	public void deleteSecGrpIncByGroupIdx( CFSecAuthorization Authorization,
		CFSecSecGrpIncByGroupIdxKey argKey )
	{
		CFSecSecGrpIncBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGrpIncBuff> matchSet = new LinkedList<CFSecSecGrpIncBuff>();
		Iterator<CFSecSecGrpIncBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGrpIncBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecGrpIncId() );
			deleteSecGrpInc( Authorization, cur );
		}
	}

	public void deleteSecGrpIncByIncludeIdx( CFSecAuthorization Authorization,
		long argClusterId,
		int argIncludeGroupId )
	{
		CFSecSecGrpIncByIncludeIdxKey key = schema.getFactorySecGrpInc().newIncludeIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredIncludeGroupId( argIncludeGroupId );
		deleteSecGrpIncByIncludeIdx( Authorization, key );
	}

	public void deleteSecGrpIncByIncludeIdx( CFSecAuthorization Authorization,
		CFSecSecGrpIncByIncludeIdxKey argKey )
	{
		CFSecSecGrpIncBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGrpIncBuff> matchSet = new LinkedList<CFSecSecGrpIncBuff>();
		Iterator<CFSecSecGrpIncBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGrpIncBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecGrpIncId() );
			deleteSecGrpInc( Authorization, cur );
		}
	}

	public void deleteSecGrpIncByUIncludeIdx( CFSecAuthorization Authorization,
		long argClusterId,
		int argSecGroupId,
		int argIncludeGroupId )
	{
		CFSecSecGrpIncByUIncludeIdxKey key = schema.getFactorySecGrpInc().newUIncludeIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredSecGroupId( argSecGroupId );
		key.setRequiredIncludeGroupId( argIncludeGroupId );
		deleteSecGrpIncByUIncludeIdx( Authorization, key );
	}

	public void deleteSecGrpIncByUIncludeIdx( CFSecAuthorization Authorization,
		CFSecSecGrpIncByUIncludeIdxKey argKey )
	{
		CFSecSecGrpIncBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGrpIncBuff> matchSet = new LinkedList<CFSecSecGrpIncBuff>();
		Iterator<CFSecSecGrpIncBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGrpIncBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecGrpIncId() );
			deleteSecGrpInc( Authorization, cur );
		}
	}

	public void releasePreparedStatements() {
	}
}
