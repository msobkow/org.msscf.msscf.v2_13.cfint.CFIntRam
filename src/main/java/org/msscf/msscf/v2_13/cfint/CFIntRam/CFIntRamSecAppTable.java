
// Description: Java 11 in-memory RAM DbIO implementation for SecApp.

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
 *	CFIntRamSecAppTable in-memory RAM DbIO implementation
 *	for SecApp.
 */
public class CFIntRamSecAppTable
	implements ICFIntSecAppTable
{
	private ICFIntSchema schema;
	private Map< CFSecSecAppPKey,
				CFSecSecAppBuff > dictByPKey
		= new HashMap< CFSecSecAppPKey,
				CFSecSecAppBuff >();
	private Map< CFSecSecAppByClusterIdxKey,
				Map< CFSecSecAppPKey,
					CFSecSecAppBuff >> dictByClusterIdx
		= new HashMap< CFSecSecAppByClusterIdxKey,
				Map< CFSecSecAppPKey,
					CFSecSecAppBuff >>();
	private Map< CFSecSecAppByUJEEMountIdxKey,
			CFSecSecAppBuff > dictByUJEEMountIdx
		= new HashMap< CFSecSecAppByUJEEMountIdxKey,
			CFSecSecAppBuff >();

	public CFIntRamSecAppTable( ICFIntSchema argSchema ) {
		schema = argSchema;
	}

	public void createSecApp( CFSecAuthorization Authorization,
		CFSecSecAppBuff Buff )
	{
		final String S_ProcName = "createSecApp";
		CFSecSecAppPKey pkey = schema.getFactorySecApp().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredSecAppId( ((CFIntRamClusterTable)schema.getTableCluster()).nextSecAppIdGen( Authorization,
			Buff.getRequiredClusterId() ) );
		Buff.setRequiredClusterId( pkey.getRequiredClusterId() );
		Buff.setRequiredSecAppId( pkey.getRequiredSecAppId() );
		CFSecSecAppByClusterIdxKey keyClusterIdx = schema.getFactorySecApp().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecSecAppByUJEEMountIdxKey keyUJEEMountIdx = schema.getFactorySecApp().newUJEEMountIdxKey();
		keyUJEEMountIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUJEEMountIdx.setRequiredJEEMountName( Buff.getRequiredJEEMountName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUJEEMountIdx.containsKey( keyUJEEMountIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecAppUJEEMountIdx",
				keyUJEEMountIdx );
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
						"SecAppCluster",
						"Cluster",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecSecAppPKey, CFSecSecAppBuff > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< CFSecSecAppPKey, CFSecSecAppBuff >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

		dictByUJEEMountIdx.put( keyUJEEMountIdx, Buff );

	}

	public CFSecSecAppBuff readDerived( CFSecAuthorization Authorization,
		CFSecSecAppPKey PKey )
	{
		final String S_ProcName = "CFIntRamSecApp.readDerived";
		CFSecSecAppPKey key = schema.getFactorySecApp().newPKey();
		key.setRequiredClusterId( PKey.getRequiredClusterId() );
		key.setRequiredSecAppId( PKey.getRequiredSecAppId() );
		CFSecSecAppBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecAppBuff lockDerived( CFSecAuthorization Authorization,
		CFSecSecAppPKey PKey )
	{
		final String S_ProcName = "CFIntRamSecApp.readDerived";
		CFSecSecAppPKey key = schema.getFactorySecApp().newPKey();
		key.setRequiredClusterId( PKey.getRequiredClusterId() );
		key.setRequiredSecAppId( PKey.getRequiredSecAppId() );
		CFSecSecAppBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecAppBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFIntRamSecApp.readAllDerived";
		CFSecSecAppBuff[] retList = new CFSecSecAppBuff[ dictByPKey.values().size() ];
		Iterator< CFSecSecAppBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecSecAppBuff[] readDerivedByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFIntRamSecApp.readDerivedByClusterIdx";
		CFSecSecAppByClusterIdxKey key = schema.getFactorySecApp().newClusterIdxKey();
		key.setRequiredClusterId( ClusterId );

		CFSecSecAppBuff[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< CFSecSecAppPKey, CFSecSecAppBuff > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new CFSecSecAppBuff[ subdictClusterIdx.size() ];
			Iterator< CFSecSecAppBuff > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecAppPKey, CFSecSecAppBuff > subdictClusterIdx
				= new HashMap< CFSecSecAppPKey, CFSecSecAppBuff >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new CFSecSecAppBuff[0];
		}
		return( recArray );
	}

	public CFSecSecAppBuff readDerivedByUJEEMountIdx( CFSecAuthorization Authorization,
		long ClusterId,
		String JEEMountName )
	{
		final String S_ProcName = "CFIntRamSecApp.readDerivedByUJEEMountIdx";
		CFSecSecAppByUJEEMountIdxKey key = schema.getFactorySecApp().newUJEEMountIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredJEEMountName( JEEMountName );

		CFSecSecAppBuff buff;
		if( dictByUJEEMountIdx.containsKey( key ) ) {
			buff = dictByUJEEMountIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecAppBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecAppId )
	{
		final String S_ProcName = "CFIntRamSecApp.readDerivedByIdIdx() ";
		CFSecSecAppPKey key = schema.getFactorySecApp().newPKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredSecAppId( SecAppId );

		CFSecSecAppBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecAppBuff readBuff( CFSecAuthorization Authorization,
		CFSecSecAppPKey PKey )
	{
		final String S_ProcName = "CFIntRamSecApp.readBuff";
		CFSecSecAppBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a009" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecAppBuff lockBuff( CFSecAuthorization Authorization,
		CFSecSecAppPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecSecAppBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a009" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecAppBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFIntRamSecApp.readAllBuff";
		CFSecSecAppBuff buff;
		ArrayList<CFSecSecAppBuff> filteredList = new ArrayList<CFSecSecAppBuff>();
		CFSecSecAppBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a009" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecSecAppBuff[0] ) );
	}

	/**
	 *	Read a page of all the specific SecApp buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecApp instances in the database accessible for the Authorization.
	 */
	public CFSecSecAppBuff[] pageAllBuff( CFSecAuthorization Authorization,
		Long priorClusterId,
		Integer priorSecAppId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public CFSecSecAppBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecAppId )
	{
		final String S_ProcName = "CFIntRamSecApp.readBuffByIdIdx() ";
		CFSecSecAppBuff buff = readDerivedByIdIdx( Authorization,
			ClusterId,
			SecAppId );
		if( ( buff != null ) && buff.getClassCode().equals( "a009" ) ) {
			return( (CFSecSecAppBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecSecAppBuff[] readBuffByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFIntRamSecApp.readBuffByClusterIdx() ";
		CFSecSecAppBuff buff;
		ArrayList<CFSecSecAppBuff> filteredList = new ArrayList<CFSecSecAppBuff>();
		CFSecSecAppBuff[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a009" ) ) {
				filteredList.add( (CFSecSecAppBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecAppBuff[0] ) );
	}

	public CFSecSecAppBuff readBuffByUJEEMountIdx( CFSecAuthorization Authorization,
		long ClusterId,
		String JEEMountName )
	{
		final String S_ProcName = "CFIntRamSecApp.readBuffByUJEEMountIdx() ";
		CFSecSecAppBuff buff = readDerivedByUJEEMountIdx( Authorization,
			ClusterId,
			JEEMountName );
		if( ( buff != null ) && buff.getClassCode().equals( "a009" ) ) {
			return( (CFSecSecAppBuff)buff );
		}
		else {
			return( null );
		}
	}

	/**
	 *	Read a page array of the specific SecApp buffer instances identified by the duplicate key ClusterIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argClusterId	The SecApp key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecAppBuff[] pageBuffByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId,
		Long priorClusterId,
		Integer priorSecAppId )
	{
		final String S_ProcName = "pageBuffByClusterIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public void updateSecApp( CFSecAuthorization Authorization,
		CFSecSecAppBuff Buff )
	{
		CFSecSecAppPKey pkey = schema.getFactorySecApp().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredSecAppId( Buff.getRequiredSecAppId() );
		CFSecSecAppBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecApp",
				"Existing record not found",
				"SecApp",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecApp",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecSecAppByClusterIdxKey existingKeyClusterIdx = schema.getFactorySecApp().newClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecSecAppByClusterIdxKey newKeyClusterIdx = schema.getFactorySecApp().newClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecSecAppByUJEEMountIdxKey existingKeyUJEEMountIdx = schema.getFactorySecApp().newUJEEMountIdxKey();
		existingKeyUJEEMountIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUJEEMountIdx.setRequiredJEEMountName( existing.getRequiredJEEMountName() );

		CFSecSecAppByUJEEMountIdxKey newKeyUJEEMountIdx = schema.getFactorySecApp().newUJEEMountIdxKey();
		newKeyUJEEMountIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUJEEMountIdx.setRequiredJEEMountName( Buff.getRequiredJEEMountName() );

		// Check unique indexes

		if( ! existingKeyUJEEMountIdx.equals( newKeyUJEEMountIdx ) ) {
			if( dictByUJEEMountIdx.containsKey( newKeyUJEEMountIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecApp",
					"SecAppUJEEMountIdx",
					newKeyUJEEMountIdx );
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
						"updateSecApp",
						"Container",
						"SecAppCluster",
						"Cluster",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecSecAppPKey, CFSecSecAppBuff > subdict;

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
			subdict = new HashMap< CFSecSecAppPKey, CFSecSecAppBuff >();
			dictByClusterIdx.put( newKeyClusterIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUJEEMountIdx.remove( existingKeyUJEEMountIdx );
		dictByUJEEMountIdx.put( newKeyUJEEMountIdx, Buff );

	}

	public void deleteSecApp( CFSecAuthorization Authorization,
		CFSecSecAppBuff Buff )
	{
		final String S_ProcName = "CFIntRamSecAppTable.deleteSecApp() ";
		String classCode;
		CFSecSecAppPKey pkey = schema.getFactorySecApp().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredSecAppId( Buff.getRequiredSecAppId() );
		CFSecSecAppBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecApp",
				pkey );
		}
					schema.getTableSecForm().deleteSecFormBySecAppIdx( Authorization,
						existing.getRequiredClusterId(),
						existing.getRequiredSecAppId() );
		CFSecSecAppByClusterIdxKey keyClusterIdx = schema.getFactorySecApp().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecSecAppByUJEEMountIdxKey keyUJEEMountIdx = schema.getFactorySecApp().newUJEEMountIdxKey();
		keyUJEEMountIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUJEEMountIdx.setRequiredJEEMountName( existing.getRequiredJEEMountName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecSecAppPKey, CFSecSecAppBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

		dictByUJEEMountIdx.remove( keyUJEEMountIdx );

	}
	public void deleteSecAppByIdIdx( CFSecAuthorization Authorization,
		long argClusterId,
		int argSecAppId )
	{
		CFSecSecAppPKey key = schema.getFactorySecApp().newPKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredSecAppId( argSecAppId );
		deleteSecAppByIdIdx( Authorization, key );
	}

	public void deleteSecAppByIdIdx( CFSecAuthorization Authorization,
		CFSecSecAppPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecSecAppBuff cur;
		LinkedList<CFSecSecAppBuff> matchSet = new LinkedList<CFSecSecAppBuff>();
		Iterator<CFSecSecAppBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecAppBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecApp().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecAppId() );
			deleteSecApp( Authorization, cur );
		}
	}

	public void deleteSecAppByClusterIdx( CFSecAuthorization Authorization,
		long argClusterId )
	{
		CFSecSecAppByClusterIdxKey key = schema.getFactorySecApp().newClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteSecAppByClusterIdx( Authorization, key );
	}

	public void deleteSecAppByClusterIdx( CFSecAuthorization Authorization,
		CFSecSecAppByClusterIdxKey argKey )
	{
		CFSecSecAppBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecAppBuff> matchSet = new LinkedList<CFSecSecAppBuff>();
		Iterator<CFSecSecAppBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecAppBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecApp().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecAppId() );
			deleteSecApp( Authorization, cur );
		}
	}

	public void deleteSecAppByUJEEMountIdx( CFSecAuthorization Authorization,
		long argClusterId,
		String argJEEMountName )
	{
		CFSecSecAppByUJEEMountIdxKey key = schema.getFactorySecApp().newUJEEMountIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredJEEMountName( argJEEMountName );
		deleteSecAppByUJEEMountIdx( Authorization, key );
	}

	public void deleteSecAppByUJEEMountIdx( CFSecAuthorization Authorization,
		CFSecSecAppByUJEEMountIdxKey argKey )
	{
		CFSecSecAppBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecAppBuff> matchSet = new LinkedList<CFSecSecAppBuff>();
		Iterator<CFSecSecAppBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecAppBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecApp().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecAppId() );
			deleteSecApp( Authorization, cur );
		}
	}

	public void releasePreparedStatements() {
	}
}
